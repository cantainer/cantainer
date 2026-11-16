//! A can as an OCI image layout directory (`git.can/`): `oci-layout`, `index.json` and
//! `blobs/sha256/…`. The registry code will move the same blobs (spec §2).
//!
//! The OCI types here are the small subset a can uses, written out rather than taken from a
//! crate: the reader checks every field it relies on, and the core `cant` stays free of the
//! larger OCI dependency until registry support needs it.

use std::collections::BTreeMap;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use cant_store::Digest;
use serde::{Deserialize, Serialize};

use crate::Error;

pub const ARTIFACT_TYPE: &str = "application/vnd.cantainer.can.v1";
pub const CONFIG_MEDIA_TYPE: &str = "application/vnd.cantainer.can.manifest.v1+toml";
pub const FILE_MEDIA_TYPE: &str = "application/vnd.cantainer.can.file.v1";
pub const BUNDLE_MEDIA_TYPE: &str = "application/vnd.cantainer.can.bundle.v1";
pub const SBOM_MEDIA_TYPE: &str = "application/vnd.cyclonedx+json";
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const FORMAT_ANNOTATION: &str = "org.cantainer.can.format";
pub const REF_ANNOTATION: &str = "org.opencontainers.image.ref.name";

/// Largest JSON or TOML document (index, manifest, config, tree) read into memory.
const MAX_DOCUMENT: u64 = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Platform {
    pub architecture: String,
    pub os: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Descriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

impl Descriptor {
    pub fn new(media_type: &str, digest: Digest, size: u64) -> Self {
        Descriptor {
            media_type: media_type.into(),
            digest: digest.to_string(),
            size,
            artifact_type: None,
            platform: None,
            annotations: BTreeMap::new(),
        }
    }

    fn parsed_digest(&self) -> Result<Digest, Error> {
        self.digest
            .parse()
            .map_err(|_| Error::Invalid(vec![format!("bad digest `{}`", self.digest)]))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageManifest {
    pub schema_version: u32,
    pub media_type: String,
    #[serde(default)]
    pub artifact_type: Option<String>,
    pub config: Descriptor,
    pub layers: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageIndex {
    pub schema_version: u32,
    pub media_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
    pub manifests: Vec<Descriptor>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// The OCI platform names of this machine.
pub fn this_platform() -> Platform {
    let architecture = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "riscv64" => "riscv64",
        other => other,
    };
    Platform {
        architecture: architecture.into(),
        os: std::env::consts::OS.into(),
    }
}

fn io_err(path: &Path, e: io::Error) -> Error {
    Error::Io {
        path: path.to_path_buf(),
        source: e,
    }
}

// ---- writing ---------------------------------------------------------------------------------

/// Writes blobs into a new layout directory.
#[derive(Debug)]
pub struct Writer {
    dir: PathBuf,
}

impl Writer {
    /// Creates the layout directory, which must not exist yet.
    pub fn create(dir: &Path) -> Result<Self, Error> {
        std::fs::create_dir(dir).map_err(|e| io_err(dir, e))?;
        std::fs::create_dir_all(dir.join("blobs/sha256")).map_err(|e| io_err(dir, e))?;
        std::fs::write(
            dir.join("oci-layout"),
            "{\"imageLayoutVersion\":\"1.0.0\"}\n",
        )
        .map_err(|e| io_err(dir, e))?;
        Ok(Writer {
            dir: dir.to_path_buf(),
        })
    }

    fn blob_path(&self, d: &Digest) -> PathBuf {
        self.dir.join("blobs/sha256").join(d.hex())
    }

    /// Adds bytes as a blob.
    pub fn put_bytes(&self, media_type: &str, bytes: &[u8]) -> Result<Descriptor, Error> {
        let d = Digest::of_bytes(bytes);
        let path = self.blob_path(&d);
        if !path.exists() {
            std::fs::write(&path, bytes).map_err(|e| io_err(&path, e))?;
        }
        Ok(Descriptor::new(media_type, d, bytes.len() as u64))
    }

    /// Adds a file's contents as a blob, returning its descriptor.
    pub fn put_file(&self, media_type: &str, source: &Path) -> Result<Descriptor, Error> {
        let d = Digest::of_file(source).map_err(|e| io_err(source, e))?;
        let path = self.blob_path(&d);
        if !path.exists() {
            std::fs::copy(source, &path).map_err(|e| io_err(source, e))?;
            // The copy keeps the source's mode; blobs are plain data.
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .map_err(|e| io_err(&path, e))?;
        }
        // Hash again what was written, in case the source changed while being copied.
        let written = Digest::of_file(&path).map_err(|e| io_err(&path, e))?;
        if written != d {
            return Err(Error::Invalid(vec![format!(
                "{} changed while being packed",
                source.display()
            )]));
        }
        let size = std::fs::metadata(&path)
            .map_err(|e| io_err(&path, e))?
            .len();
        Ok(Descriptor::new(media_type, d, size))
    }

    /// Adds a JSON document as a blob.
    pub fn put_json<T: Serialize>(&self, media_type: &str, value: &T) -> Result<Descriptor, Error> {
        let bytes = serde_json::to_vec(value).map_err(|e| Error::Invalid(vec![e.to_string()]))?;
        self.put_bytes(media_type, &bytes)
    }

    /// Writes `index.json`, which points at the can's index.
    pub fn finish(self, can_index: Descriptor) -> Result<(), Error> {
        let top = ImageIndex {
            schema_version: 2,
            media_type: INDEX_MEDIA_TYPE.into(),
            artifact_type: None,
            manifests: vec![can_index],
            annotations: BTreeMap::new(),
        };
        let bytes =
            serde_json::to_vec_pretty(&top).map_err(|e| Error::Invalid(vec![e.to_string()]))?;
        let path = self.dir.join("index.json");
        std::fs::write(&path, bytes).map_err(|e| io_err(&path, e))
    }
}

// ---- reading ---------------------------------------------------------------------------------

/// A layout directory being read. Every blob is checked against its descriptor.
#[derive(Debug)]
pub struct Reader {
    dir: PathBuf,
}

/// The parts of a can for this platform.
#[derive(Debug)]
pub struct Can {
    pub manifest_digest: Digest,
    pub manifest: ImageManifest,
    pub config: Vec<u8>,
    pub tree: Vec<u8>,
    pub sbom: Vec<u8>,
}

impl Reader {
    pub fn open(dir: &Path) -> Result<Self, Error> {
        let marker = dir.join("oci-layout");
        let text = std::fs::read_to_string(&marker).map_err(|e| io_err(&marker, e))?;
        if !text.contains("\"1.0.0\"") {
            return Err(Error::Invalid(vec![format!(
                "{}: unsupported OCI layout version",
                dir.display()
            )]));
        }
        Ok(Reader {
            dir: dir.to_path_buf(),
        })
    }

    /// Path of a blob in the layout (the digest is validated, so it can't escape `blobs/`).
    pub fn blob_path(&self, digest: &Digest) -> PathBuf {
        self.dir.join("blobs/sha256").join(digest.hex())
    }

    /// Reads a small blob and checks it against the descriptor.
    fn read_doc(&self, desc: &Descriptor) -> Result<Vec<u8>, Error> {
        let d = desc.parsed_digest()?;
        if desc.size > MAX_DOCUMENT {
            return Err(Error::Invalid(vec![format!(
                "{} is too large",
                desc.digest
            )]));
        }
        let path = self.blob_path(&d);
        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .map_err(|e| io_err(&path, e))?
            .take(desc.size + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| io_err(&path, e))?;
        if bytes.len() as u64 != desc.size || Digest::of_bytes(&bytes) != d {
            return Err(Error::Invalid(vec![format!(
                "blob {} doesn't match its descriptor",
                desc.digest
            )]));
        }
        Ok(bytes)
    }

    fn parse<T: for<'de> Deserialize<'de>>(bytes: &[u8], what: &str) -> Result<T, Error> {
        serde_json::from_slice(bytes).map_err(|e| Error::Invalid(vec![format!("{what}: {e}")]))
    }

    /// Finds the can's manifest for this machine and reads its small parts.
    pub fn can(&self) -> Result<Can, Error> {
        let index_path = self.dir.join("index.json");
        let top_bytes = std::fs::read(&index_path).map_err(|e| io_err(&index_path, e))?;
        let top: ImageIndex = Self::parse(&top_bytes, "index.json")?;
        let [entry] = top.manifests.as_slice() else {
            return Err(Error::Invalid(vec![
                "index.json must point at exactly one can".into(),
            ]));
        };
        let platform = this_platform();
        let manifest_desc = match entry.media_type.as_str() {
            INDEX_MEDIA_TYPE => {
                let index: ImageIndex = Self::parse(&self.read_doc(entry)?, "can index")?;
                if index.artifact_type.as_deref() != Some(ARTIFACT_TYPE) {
                    return Err(Error::Invalid(vec!["not a can (artifactType)".into()]));
                }
                index
                    .manifests
                    .into_iter()
                    .find(|m| m.platform.as_ref() == Some(&platform))
                    .ok_or_else(|| {
                        Error::Invalid(vec![format!(
                            "this can has no build for {}/{}",
                            platform.os, platform.architecture
                        )])
                    })?
            }
            MANIFEST_MEDIA_TYPE => entry.clone(),
            other => {
                return Err(Error::Invalid(vec![format!(
                    "unexpected media type {other}"
                )]));
            }
        };
        if manifest_desc.media_type != MANIFEST_MEDIA_TYPE {
            return Err(Error::Invalid(vec![
                "platform entry is not an image manifest".into(),
            ]));
        }
        let manifest_bytes = self.read_doc(&manifest_desc)?;
        let manifest: ImageManifest = Self::parse(&manifest_bytes, "manifest")?;
        if manifest.artifact_type.as_deref() != Some(ARTIFACT_TYPE)
            || manifest.config.media_type != CONFIG_MEDIA_TYPE
        {
            return Err(Error::Invalid(vec!["not a can manifest".into()]));
        }
        match manifest
            .annotations
            .get(FORMAT_ANNOTATION)
            .map(String::as_str)
        {
            Some("1") => {}
            other => {
                return Err(Error::Invalid(vec![format!(
                    "can format {} is not supported (this cant reads format 1)",
                    other.unwrap_or("(missing)")
                )]));
            }
        }
        let [tree_desc, sbom_desc, ..] = manifest.layers.as_slice() else {
            return Err(Error::Invalid(vec![
                "a can needs a tree and an SBOM".into(),
            ]));
        };
        if tree_desc.media_type != crate::tree::MEDIA_TYPE
            || sbom_desc.media_type != SBOM_MEDIA_TYPE
        {
            return Err(Error::Invalid(vec![
                "layers 0 and 1 must be the tree and the SBOM".into(),
            ]));
        }
        let config = self.read_doc(&manifest.config)?;
        let tree = self.read_doc(tree_desc)?;
        let sbom = self.read_doc(sbom_desc)?;
        Ok(Can {
            manifest_digest: manifest_desc.parsed_digest()?,
            manifest,
            config,
            tree,
            sbom,
        })
    }
}
