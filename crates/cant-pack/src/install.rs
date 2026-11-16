//! Installing a can: verify every blob into the store, then build the can's root as hard
//! links to the stored objects (`docs/CANS.md` §2).
//!
//! ```text
//! <data>/store/                     cant_store::FsStore
//! <data>/cans/<manifest digest>/    manifest.json  config.toml  tree.json  sbom.json  complete
//!                                   root/   the can's files, laid out per tree.json
//! ```
//!
//! The root is built in a fresh temporary directory and renamed into place, so a half-built
//! can is never used. Paths come from a validated tree (no `..`, no absolute paths, every
//! parent a directory entry), and nothing is created through a symlink, because the tree has
//! no symlink that is also a parent.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use cant_manifest::{CAN_MANIFEST_VERSION, Manifest};
use cant_store::{Digest, FsStore};

use crate::Error;
use crate::layout::{BUNDLE_MEDIA_TYPE, FILE_MEDIA_TYPE, Reader};
use crate::tree::{Kind, Limits, Tree};

/// An installed can.
#[derive(Debug, Clone)]
pub struct Installed {
    pub digest: Digest,
    pub dir: PathBuf,
    pub root: PathBuf,
    pub manifest: Manifest,
    pub tree: Tree,
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> Error + '_ {
    move |e| Error::Io {
        path: path.to_path_buf(),
        source: e,
    }
}

/// Checks that a can's manifest and tree agree, and parses both.
fn parse(config: &[u8], tree: &[u8]) -> Result<(Manifest, Tree), Error> {
    let text = std::str::from_utf8(config)
        .map_err(|_| Error::Invalid(vec!["manifest is not UTF-8".into()]))?;
    let manifest =
        Manifest::from_toml_str(text).map_err(|e| Error::Invalid(vec![e.to_string()]))?;
    if manifest.manifest_version != CAN_MANIFEST_VERSION {
        return Err(Error::Invalid(vec![
            "a can's manifest must have manifest_version = 2".into(),
        ]));
    }
    let tree: Tree =
        serde_json::from_slice(tree).map_err(|e| Error::Invalid(vec![format!("tree: {e}")]))?;
    tree.validate(&Limits::default()).map_err(Error::Invalid)?;
    let expected = format!("$CAN/{}", tree.entrypoint.path);
    if manifest.entrypoint.path != expected {
        return Err(Error::Invalid(vec![format!(
            "the manifest runs {} but the tree's entrypoint is {expected}",
            manifest.entrypoint.path
        )]));
    }
    Ok((manifest, tree))
}

/// Installs the can in the layout directory `layout` (or finds it already installed).
pub fn install(layout: &Path, data: &Path) -> Result<Installed, Error> {
    let reader = Reader::open(layout)?;
    let can = reader.can()?;
    let (manifest, tree) = parse(&can.config, &can.tree)?;
    let cans = data.join("cans");
    let dir = cans.join(can.manifest_digest.hex());
    if dir.join("complete").is_file() {
        return open_installed(&dir);
    }

    // Every blob the tree needs must be a layer of the manifest (spec §2.2), and is verified
    // on its way into the store.
    let store = FsStore::open(&data.join("store")).map_err(io(data))?;
    let layer_digests: std::collections::BTreeSet<&str> = can
        .manifest
        .layers
        .iter()
        .map(|l| l.digest.as_str())
        .collect();
    for l in &can.manifest.layers[2..] {
        if l.media_type != FILE_MEDIA_TYPE && l.media_type != BUNDLE_MEDIA_TYPE {
            return Err(Error::Invalid(vec![format!(
                "unexpected layer type {}",
                l.media_type
            )]));
        }
    }
    for e in tree.entries.iter().filter(|e| e.kind == Kind::File) {
        let d = e.file_digest().expect("validated");
        match &e.bundle {
            None => {
                if !layer_digests.contains(d.to_string().as_str()) {
                    return Err(Error::Invalid(vec![format!(
                        "{} is not a layer of the manifest",
                        e.path
                    )]));
                }
                if !store.has(&d) {
                    store.put_file(&reader.blob_path(&d), Some(&d))?;
                }
            }
            Some(b) => {
                let bd: Digest = b.digest.parse().expect("validated");
                if !layer_digests.contains(b.digest.as_str()) {
                    return Err(Error::Invalid(vec![format!(
                        "bundle of {} is not a layer",
                        e.path
                    )]));
                }
                if !store.has(&d) {
                    let path = reader.blob_path(&bd);
                    let mut f = std::fs::File::open(&path).map_err(io(&path))?;
                    f.seek(SeekFrom::Start(b.offset)).map_err(io(&path))?;
                    store.put_reader(f.take(b.length), Some(&d))?;
                }
            }
        }
    }

    // Build the root next to its final place, then rename it there.
    std::fs::create_dir_all(&cans).map_err(io(&cans))?;
    let tmp = cans.join(format!(
        ".tmp-{}-{}",
        can.manifest_digest.hex(),
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    let root = tmp.join("root");
    std::fs::create_dir_all(&root).map_err(io(&root))?;
    let built = (|| {
        for e in &tree.entries {
            let at = root.join(&e.path);
            match e.kind {
                Kind::Dir => std::fs::create_dir(&at).map_err(io(&at))?,
                Kind::Symlink => {
                    std::os::unix::fs::symlink(e.target.as_deref().expect("validated"), &at)
                        .map_err(io(&at))?;
                }
                Kind::File => {
                    let obj = store.path_of(&e.file_digest().expect("validated"));
                    if std::fs::hard_link(&obj, &at).is_err() {
                        // Another filesystem: copy, with the object's mode.
                        std::fs::copy(&obj, &at).map_err(io(&at))?;
                    }
                }
            }
        }
        for (name, bytes) in [
            (
                "manifest.json",
                serde_json::to_vec(&can.manifest).unwrap_or_default(),
            ),
            ("config.toml", can.config.clone()),
            ("tree.json", can.tree.clone()),
            ("sbom.json", can.sbom.clone()),
        ] {
            std::fs::write(tmp.join(name), bytes).map_err(io(&tmp))?;
        }
        std::fs::write(tmp.join("complete"), b"").map_err(io(&tmp))
    })();
    if let Err(e) = built {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(e);
    }
    if std::fs::rename(&tmp, &dir).is_err() {
        // Installed concurrently by another `cant`.
        let _ = std::fs::remove_dir_all(&tmp);
    }
    let installed = open_installed(&dir)?;
    debug_assert_eq!(installed.manifest, manifest);
    Ok(installed)
}

/// Opens an installed can and checks it before use: the manifest and tree parse and agree,
/// the program and its loader hash to their digests, and every other file has its size.
pub fn open_installed(dir: &Path) -> Result<Installed, Error> {
    let digest: Digest = format!(
        "sha256:{}",
        dir.file_name().and_then(|n| n.to_str()).unwrap_or_default()
    )
    .parse()
    .map_err(|_| Error::Invalid(vec![format!("{}: not an installed can", dir.display())]))?;
    let read = |name: &str| {
        let p = dir.join(name);
        std::fs::read(&p).map_err(io(&p))
    };
    let (manifest, tree) = parse(&read("config.toml")?, &read("tree.json")?)?;
    let root = dir.join("root");
    let critical: Vec<&str> = std::iter::once(tree.entrypoint.path.as_str())
        .chain(tree.entrypoint.loader.as_deref())
        .collect();
    for e in tree.entries.iter().filter(|e| e.kind == Kind::File) {
        let at = root.join(&e.path);
        let meta = std::fs::symlink_metadata(&at).map_err(io(&at))?;
        if !meta.is_file() || Some(meta.len()) != e.size {
            return Err(Error::Invalid(vec![format!(
                "{}: changed since it was installed",
                at.display()
            )]));
        }
        if critical.contains(&e.path.as_str()) {
            let actual = Digest::of_file(&at).map_err(io(&at))?;
            if Some(actual) != e.file_digest() {
                return Err(Error::Invalid(vec![format!(
                    "{}: changed since it was installed",
                    at.display()
                )]));
            }
        }
    }
    Ok(Installed {
        digest,
        dir: dir.to_path_buf(),
        root,
        manifest,
        tree,
    })
}
