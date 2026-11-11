//! Content-addressed storage for Cantainer.
//!
//! Today this crate provides [`Digest`] (SHA-256 identities for files) and the [`Store`]
//! interface. There is no store implementation yet. The plan (see `docs/VISION.md`) is a
//! per-file content-addressed store, later backed by composefs and fs-verity, filled from
//! OCI registries.

#![forbid(unsafe_code)]

use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};

/// A SHA-256 content digest, written `sha256:<64 hex digits>` (the OCI convention).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Digest of a byte slice.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Digest(Sha256::digest(bytes).into())
    }

    /// Digest of everything a reader yields.
    pub fn of_reader(mut reader: impl Read) -> io::Result<Self> {
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            hasher.update(&buf[..n]);
        }
        Ok(Digest(hasher.finalize().into()))
    }

    /// Digest of a file's contents.
    pub fn of_file(path: &Path) -> io::Result<Self> {
        Self::of_reader(std::fs::File::open(path)?)
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Error parsing a digest string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid digest `{0}` (expected sha256:<64 lowercase hex digits>)")]
pub struct ParseDigestError(String);

impl FromStr for Digest {
    type Err = ParseDigestError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || ParseDigestError(s.to_owned());
        let hex = s.strip_prefix("sha256:").ok_or_else(err)?;
        if hex.len() != 64 {
            return Err(err());
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let pair = &hex[2 * i..2 * i + 2];
            if !pair
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(err());
            }
            *byte = u8::from_str_radix(pair, 16).map_err(|_| err())?;
        }
        Ok(Digest(out))
    }
}

/// Errors from a [`Store`].
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The object is not in the store.
    #[error("{0} not found in store")]
    NotFound(Digest),
    /// The stored bytes do not match their digest.
    #[error("corrupt object: expected {expected}, found {actual}")]
    Corrupt {
        /// The digest asked for.
        expected: Digest,
        /// The digest of what was read.
        actual: Digest,
    },
    /// I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// A content-addressed store of files. Objects are immutable and named by their digest.
///
/// Not implemented yet: no type in this crate implements it.
pub trait Store {
    /// Whether the store holds `digest`.
    fn contains(&self, digest: &Digest) -> Result<bool, StoreError>;
    /// Adds bytes and returns their digest.
    fn put(&self, bytes: &[u8]) -> Result<Digest, StoreError>;
    /// Reads an object, verifying its digest.
    fn get(&self, digest: &Digest) -> Result<Vec<u8>, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // SHA-256 of "abc" (FIPS 180-2 test vector).
        let d = Digest::of_bytes(b"abc");
        assert_eq!(
            d.to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(d.to_string().parse::<Digest>(), Ok(d));
    }

    #[test]
    fn file_and_reader_agree() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f");
        let data = vec![7u8; 200_000];
        std::fs::write(&path, &data).expect("write");
        assert_eq!(
            Digest::of_file(&path).expect("hash"),
            Digest::of_bytes(&data)
        );
    }

    #[test]
    fn rejects_malformed() {
        for s in [
            "",
            "sha256:",
            "md5:00",
            "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD",
            "sha256:+a7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ] {
            assert!(s.parse::<Digest>().is_err(), "{s}");
        }
    }
}
