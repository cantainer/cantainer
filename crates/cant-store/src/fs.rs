//! A content-addressed store in a directory.
//!
//! ```text
//! <root>/blobs/sha256/ab/abcdef…   one file per digest, mode 0555, never modified
//! <root>/tmp/                       incoming files, renamed into place once verified
//! ```
//!
//! Objects are written to `tmp/` while being hashed and only renamed to their name once the
//! digest is known (and matches the expected one, if given), so a reader never sees a partial or
//! wrong object under a digest's name. Objects are mode 0555: the same object is hard-linked into
//! every can that contains it, hard links share one mode, and some of those files are programs.

use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

use crate::{Digest, Store, StoreError};

/// Mode of stored objects.
const OBJECT_MODE: u32 = 0o555;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A content-addressed store rooted at a directory.
#[derive(Debug, Clone)]
pub struct FsStore {
    root: PathBuf,
}

impl FsStore {
    /// Opens (creating if needed) the store at `root`.
    pub fn open(root: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(root.join("blobs/sha256"))?;
        std::fs::create_dir_all(root.join("tmp"))?;
        Ok(FsStore {
            root: root.to_path_buf(),
        })
    }

    /// The store's directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where the object `digest` lives (whether or not it is present).
    pub fn path_of(&self, digest: &Digest) -> PathBuf {
        let hex = digest.hex();
        self.root.join("blobs/sha256").join(&hex[..2]).join(hex)
    }

    /// Whether the object is present (not verified).
    pub fn has(&self, digest: &Digest) -> bool {
        std::fs::symlink_metadata(self.path_of(digest)).is_ok_and(|m| m.file_type().is_file())
    }

    fn temp_path(&self) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        self.root
            .join("tmp")
            .join(format!("{}-{n}-{nanos}", std::process::id()))
    }

    /// Adds everything `reader` yields. If `expected` is given, the object is stored only if it
    /// has that digest; otherwise nothing is stored and [`StoreError::Corrupt`] is returned.
    pub fn put_reader(
        &self,
        mut reader: impl Read,
        expected: Option<&Digest>,
    ) -> Result<Digest, StoreError> {
        let tmp = self.temp_path();
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 64 * 1024];
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(StoreError::Io(e)),
                };
                hasher.update(&buf[..n]);
                file.write_all(&buf[..n])?;
            }
            file.sync_all()?;
            let digest = Digest(hasher.finalize().into());
            if let Some(expected) = expected {
                if *expected != digest {
                    return Err(StoreError::Corrupt {
                        expected: *expected,
                        actual: digest,
                    });
                }
            }
            file.set_permissions(std::fs::Permissions::from_mode(OBJECT_MODE))?;
            let target = self.path_of(&digest);
            if !self.has(&digest) {
                std::fs::create_dir_all(target.parent().expect("object paths have a parent"))?;
                std::fs::rename(&tmp, &target)?;
            }
            Ok(digest)
        })();
        let _ = std::fs::remove_file(&tmp);
        result
    }

    /// Adds the contents of a file.
    pub fn put_file(&self, path: &Path, expected: Option<&Digest>) -> Result<Digest, StoreError> {
        self.put_reader(std::fs::File::open(path)?, expected)
    }

    /// Re-reads an object and checks its digest.
    pub fn verify(&self, digest: &Digest) -> Result<(), StoreError> {
        let file = match std::fs::File::open(self.path_of(digest)) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound(*digest));
            }
            Err(e) => return Err(e.into()),
        };
        let actual = Digest::of_reader(file)?;
        if actual == *digest {
            Ok(())
        } else {
            Err(StoreError::Corrupt {
                expected: *digest,
                actual,
            })
        }
    }
}

impl Store for FsStore {
    fn contains(&self, digest: &Digest) -> Result<bool, StoreError> {
        Ok(self.has(digest))
    }

    fn put(&self, bytes: &[u8]) -> Result<Digest, StoreError> {
        self.put_reader(bytes, None)
    }

    fn get(&self, digest: &Digest) -> Result<Vec<u8>, StoreError> {
        let bytes = match std::fs::read(self.path_of(digest)) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound(*digest));
            }
            Err(e) => return Err(e.into()),
        };
        let actual = Digest::of_bytes(&bytes);
        if actual == *digest {
            Ok(bytes)
        } else {
            Err(StoreError::Corrupt {
                expected: *digest,
                actual,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, FsStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let s = FsStore::open(dir.path()).expect("open");
        (dir, s)
    }

    #[test]
    fn put_get_and_dedupe() {
        let (_d, s) = store();
        let a = s.put(b"hello").expect("put");
        assert_eq!(a, Digest::of_bytes(b"hello"));
        assert_eq!(s.put(b"hello").expect("again"), a);
        assert_eq!(s.get(&a).expect("get"), b"hello");
        assert!(s.contains(&a).expect("contains"));
        let mode = std::fs::metadata(s.path_of(&a))
            .expect("stat")
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, OBJECT_MODE);
        assert_eq!(
            std::fs::read_dir(s.root().join("tmp"))
                .expect("tmp")
                .count(),
            0
        );
    }

    #[test]
    fn wrong_expected_digest_stores_nothing() {
        let (_d, s) = store();
        let wrong = Digest::of_bytes(b"something else");
        match s.put_reader(&b"hello"[..], Some(&wrong)) {
            Err(StoreError::Corrupt { expected, actual }) => {
                assert_eq!(expected, wrong);
                assert_eq!(actual, Digest::of_bytes(b"hello"));
            }
            other => panic!("expected Corrupt, got {other:?}"),
        }
        assert!(!s.has(&Digest::of_bytes(b"hello")));
        assert_eq!(
            std::fs::read_dir(s.root().join("tmp"))
                .expect("tmp")
                .count(),
            0
        );
    }

    #[test]
    fn tampering_is_detected() {
        let (_d, s) = store();
        let a = s.put(b"hello").expect("put");
        let p = s.path_of(&a);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        std::fs::write(&p, b"evil").expect("write");
        assert!(matches!(s.get(&a), Err(StoreError::Corrupt { .. })));
        assert!(matches!(s.verify(&a), Err(StoreError::Corrupt { .. })));
        assert!(matches!(
            s.verify(&Digest::of_bytes(b"absent")),
            Err(StoreError::NotFound(_))
        ));
    }
}
