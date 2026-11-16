//! Pushing cans to OCI registries and pulling them (`docs/CANS.md` §6, `spec/can-format.md`).
//!
//! - [`push`] uploads a can's layout directory: blobs the registry doesn't have yet, then each
//!   platform manifest by digest, then the can's index under the tag. Manifests are sent as the
//!   exact bytes `cant pack` wrote, so their digests in the registry are the digests in the
//!   layout.
//! - [`pull`] fetches the index, this machine's manifest, the manifest's config, tree and SBOM,
//!   and only the file blobs missing from the local store, then installs the can through
//!   `cant_pack::install`, which checks every blob against its digest.
//! - A reference such as `ghcr.io/cantainer/grep:3.11` is only recognised when its first part
//!   is a registry host (`ghcr.io`, `localhost:5000`): it can never be mistaken for a cant name
//!   or a file, and `oci-client`'s Docker Hub defaults (`grep` → `docker.io/library/grep`) never
//!   apply.
//!
//! The registry client is async; this crate runs it on a single-threaded runtime of its own, so
//! the rest of `cant` stays synchronous. TLS is rustls with the `ring` provider.

#![forbid(unsafe_code)]

use std::io::Read;
use std::path::{Path, PathBuf};

use cant_pack::layout::{
    ARTIFACT_TYPE, Descriptor, INDEX_MEDIA_TYPE, ImageIndex, ImageManifest, MANIFEST_MEDIA_TYPE,
    this_platform,
};
use cant_store::{Digest, FsStore};
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, RegistryOperation};

pub use oci_client::Reference;

/// Largest manifest or index accepted from a registry.
const MAX_MANIFEST: usize = 4 << 20;

/// Errors talking to a registry or handling what it sent.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Msg(String),
    #[error(transparent)]
    Pack(#[from] cant_pack::Error),
    #[error(transparent)]
    Store(#[from] cant_store::StoreError),
    #[error("registry: {0}")]
    Registry(#[from] oci_client::errors::OciDistributionError),
}

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

/// Whether `s` is meant as a registry reference: `HOST/REPOSITORY[:TAG][@DIGEST]`, where HOST
/// has a dot or a port, or is `localhost`.
pub fn is_reference(s: &str) -> bool {
    let Some((host, rest)) = s.split_once('/') else {
        return false;
    };
    !rest.is_empty()
        && (host.contains('.') || host.contains(':') || host == "localhost")
        && !host.starts_with('.')
        && !s.starts_with('/')
}

/// Parses a registry reference (see [`is_reference`]).
pub fn parse(s: &str) -> Result<Reference, Error> {
    if !is_reference(s) {
        return Err(msg(format!(
            "`{s}` is not a registry reference (expected HOST/NAME:TAG, e.g. ghcr.io/cantainer/grep:3.11)"
        )));
    }
    s.parse::<Reference>()
        .map_err(|e| msg(format!("`{s}` is not a valid reference: {e}")))
}

/// Credentials from `CANT_REGISTRY_USER` and `CANT_REGISTRY_TOKEN`, or anonymous.
pub fn credentials() -> RegistryAuth {
    match (
        std::env::var("CANT_REGISTRY_USER"),
        std::env::var("CANT_REGISTRY_TOKEN"),
    ) {
        (Ok(user), Ok(token)) if !user.is_empty() && !token.is_empty() => {
            RegistryAuth::Basic(user, token)
        }
        _ => RegistryAuth::Anonymous,
    }
}

/// Registries on this machine are spoken to over plain HTTP; everything else needs HTTPS.
fn is_local(registry: &str) -> bool {
    let host = registry.rsplit_once(':').map_or(registry, |(h, _)| h);
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

fn client(reference: &Reference) -> Client {
    // Errors only if a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let registry = reference.resolve_registry().to_string();
    let protocol = if is_local(&registry) {
        ClientProtocol::HttpsExcept(vec![registry])
    } else {
        ClientProtocol::Https
    };
    Client::new(ClientConfig {
        protocol,
        ..ClientConfig::default()
    })
}

fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| msg(format!("can't start the registry client: {e}")))
}

fn read_blob(layout: &Path, desc: &Descriptor) -> Result<Vec<u8>, Error> {
    let d: Digest = desc
        .digest
        .parse()
        .map_err(|_| msg(format!("bad digest {}", desc.digest)))?;
    let path = layout.join("blobs/sha256").join(d.hex());
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .and_then(|f| f.take(desc.size + 1).read_to_end(&mut bytes))
        .map_err(|e| msg(format!("{}: {e}", path.display())))?;
    if bytes.len() as u64 != desc.size || Digest::of_bytes(&bytes) != d {
        return Err(msg(format!(
            "{}: doesn't match its descriptor",
            path.display()
        )));
    }
    Ok(bytes)
}

fn json<T: serde::de::DeserializeOwned>(bytes: &[u8], what: &str) -> Result<T, Error> {
    serde_json::from_slice(bytes).map_err(|e| msg(format!("{what}: {e}")))
}

/// What [`push`] did.
#[derive(Debug)]
pub struct Pushed {
    /// Digest of the can's index, which the tag points at.
    pub digest: String,
    /// Blobs uploaded, and blobs the registry already had.
    pub uploaded: usize,
    pub skipped: usize,
}

/// Pushes the can in the layout directory `layout` to `reference` (which needs a tag).
pub fn push(layout: &Path, reference: &Reference, auth: &RegistryAuth) -> Result<Pushed, Error> {
    if reference.tag().is_none() || reference.digest().is_some() {
        return Err(msg(
            "push needs a tag, e.g. ghcr.io/you/grep:3.11, and no digest",
        ));
    }
    let top: ImageIndex = json(
        &std::fs::read(layout.join("index.json"))
            .map_err(|e| msg(format!("{}: {e}", layout.display())))?,
        "index.json",
    )?;
    let [entry] = top.manifests.as_slice() else {
        return Err(msg("index.json must point at exactly one can"));
    };
    if entry.media_type != INDEX_MEDIA_TYPE {
        return Err(msg("expected a can index in index.json"));
    }
    let index_bytes = read_blob(layout, entry)?;
    let index: ImageIndex = json(&index_bytes, "can index")?;
    if index.artifact_type.as_deref() != Some(ARTIFACT_TYPE) {
        return Err(msg("not a can"));
    }
    let client = client(reference);
    let rt = runtime()?;
    rt.block_on(async {
        client
            .auth(reference, auth, RegistryOperation::Push)
            .await?;
        let (mut uploaded, mut skipped) = (0, 0);
        for m in &index.manifests {
            let manifest_bytes = read_blob(layout, m)?;
            let manifest: ImageManifest = json(&manifest_bytes, "manifest")?;
            for blob in std::iter::once(&manifest.config).chain(&manifest.layers) {
                if client.blob_exists(reference, &blob.digest).await? {
                    skipped += 1;
                    continue;
                }
                let bytes = read_blob(layout, blob)?;
                client.push_blob(reference, bytes, &blob.digest).await?;
                uploaded += 1;
            }
            client
                .push_manifest_raw(
                    &reference.clone_with_digest(m.digest.clone()),
                    manifest_bytes,
                    http::HeaderValue::from_static(MANIFEST_MEDIA_TYPE),
                )
                .await?;
        }
        client
            .push_manifest_raw(
                reference,
                index_bytes,
                http::HeaderValue::from_static(INDEX_MEDIA_TYPE),
            )
            .await?;
        Ok(Pushed {
            digest: entry.digest.clone(),
            uploaded,
            skipped,
        })
    })
}

/// What [`pull`] did.
#[derive(Debug)]
pub struct Pulled {
    pub can: cant_pack::install::Installed,
    /// Digest of what the reference points at (the can's index).
    pub digest: String,
    pub downloaded: usize,
    pub reused: usize,
}

async fn manifest_at(
    client: &Client,
    reference: &Reference,
    auth: &RegistryAuth,
    expected: Option<&str>,
    accept: &[&str],
) -> Result<(Vec<u8>, String), Error> {
    let (bytes, _) = client.pull_manifest_raw(reference, auth, accept).await?;
    if bytes.len() > MAX_MANIFEST {
        return Err(msg("manifest too large"));
    }
    let digest = Digest::of_bytes(&bytes).to_string();
    if let Some(expected) = expected {
        if digest != expected {
            return Err(msg(format!("registry sent {digest} for {expected}")));
        }
    }
    Ok((bytes.to_vec(), digest))
}

/// Pulls `reference` and installs it under the data directory `data` (`store/`, `cans/`).
pub fn pull(reference: &Reference, data: &Path, auth: &RegistryAuth) -> Result<Pulled, Error> {
    let store =
        FsStore::open(&data.join("store")).map_err(|e| msg(format!("{}: {e}", data.display())))?;
    let staging = data.join(format!(".pull-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    let result =
        pull_into(reference, &store, &staging, auth).and_then(|(digest, downloaded, reused)| {
            let can = cant_pack::install::install(&staging, data)?;
            Ok(Pulled {
                can,
                digest,
                downloaded,
                reused,
            })
        });
    let _ = std::fs::remove_dir_all(&staging);
    let pulled = result?;
    record_ref(data, reference, &pulled)?;
    Ok(pulled)
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    std::fs::write(path, bytes).map_err(|e| msg(format!("{}: {e}", path.display())))
}

/// Downloads into a layout directory `staging`: the documents, and only the file blobs the
/// store doesn't have.
fn pull_into(
    reference: &Reference,
    store: &FsStore,
    staging: &Path,
    auth: &RegistryAuth,
) -> Result<(String, usize, usize), Error> {
    let blobs = staging.join("blobs/sha256");
    std::fs::create_dir_all(&blobs).map_err(|e| msg(format!("{}: {e}", blobs.display())))?;
    write(
        &staging.join("oci-layout"),
        b"{\"imageLayoutVersion\":\"1.0.0\"}\n",
    )?;
    let client = client(reference);
    let rt = runtime()?;
    rt.block_on(async {
        let (top_bytes, top_digest) = manifest_at(
            &client,
            reference,
            auth,
            reference.digest(),
            &[INDEX_MEDIA_TYPE, MANIFEST_MEDIA_TYPE],
        )
        .await?;
        let top: ImageIndex = json(&top_bytes, "can index")?;
        if top.artifact_type.as_deref() != Some(ARTIFACT_TYPE) {
            return Err(msg(format!("{reference} is not a can")));
        }
        let platform = this_platform();
        let mdesc = top
            .manifests
            .iter()
            .find(|m| m.platform.as_ref() == Some(&platform))
            .ok_or_else(|| {
                msg(format!(
                    "{reference} has no build for {}/{}",
                    platform.os, platform.architecture
                ))
            })?;
        let (manifest_bytes, _) = manifest_at(
            &client,
            &reference.clone_with_digest(mdesc.digest.clone()),
            auth,
            Some(&mdesc.digest),
            &[MANIFEST_MEDIA_TYPE],
        )
        .await?;
        let manifest: ImageManifest = json(&manifest_bytes, "manifest")?;
        let hex = |d: &str| d.trim_start_matches("sha256:").to_string();
        write(&blobs.join(hex(&top_digest)), &top_bytes)?;
        write(&blobs.join(hex(&mdesc.digest)), &manifest_bytes)?;

        let mut downloaded = 0;
        let mut reused = 0;
        // The config, tree and SBOM are always fetched; file blobs only if missing.
        for (i, blob) in std::iter::once(&manifest.config)
            .chain(&manifest.layers)
            .enumerate()
        {
            let d: Digest = blob
                .digest
                .parse()
                .map_err(|_| msg(format!("bad digest {}", blob.digest)))?;
            if i > 2 && store.has(&d) {
                reused += 1;
                continue;
            }
            let path = blobs.join(d.hex());
            let file = tokio::fs::File::create(&path)
                .await
                .map_err(|e| msg(format!("{}: {e}", path.display())))?;
            client
                .pull_blob(reference, blob.digest.as_str(), file)
                .await?;
            if Digest::of_file(&path).ok() != Some(d) {
                return Err(msg(format!(
                    "blob {} doesn't match its digest",
                    blob.digest
                )));
            }
            downloaded += 1;
        }
        let mut entry = Descriptor::new(
            INDEX_MEDIA_TYPE,
            top_digest.parse().map_err(|_| msg("digest"))?,
            top_bytes.len() as u64,
        );
        entry.artifact_type = Some(ARTIFACT_TYPE.into());
        let layout_index = ImageIndex {
            schema_version: 2,
            media_type: INDEX_MEDIA_TYPE.into(),
            artifact_type: None,
            manifests: vec![entry],
            annotations: Default::default(),
        };
        write(
            &staging.join("index.json"),
            &serde_json::to_vec(&layout_index).map_err(|e| msg(e.to_string()))?,
        )?;
        Ok((top_digest, downloaded, reused))
    })
}

/// Where the installed can for `reference` is recorded:
/// `refs/<registry>/<repository>/<tag or digest>`.
fn ref_path(data: &Path, reference: &Reference) -> PathBuf {
    let name = match (reference.digest(), reference.tag()) {
        (Some(d), _) => d.replace(':', "-"),
        (None, Some(t)) => format!("tag-{t}"),
        (None, None) => "tag-latest".into(),
    };
    data.join("refs")
        .join(reference.resolve_registry())
        .join(reference.repository())
        .join(name)
}

fn record_ref(data: &Path, reference: &Reference, pulled: &Pulled) -> Result<(), Error> {
    let path = ref_path(data, reference);
    std::fs::create_dir_all(path.parent().expect("has parent"))
        .map_err(|e| msg(format!("{}: {e}", path.display())))?;
    write(
        &path,
        format!("{}\n{}\n", pulled.digest, pulled.can.digest).as_bytes(),
    )
}

/// The installed can a reference was pulled as, if it was pulled.
pub fn installed(
    data: &Path,
    reference: &Reference,
) -> Result<Option<cant_pack::install::Installed>, Error> {
    let path = ref_path(data, reference);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(None);
    };
    let mut lines = text.lines();
    let (Some(_index), Some(manifest)) = (lines.next(), lines.next()) else {
        return Err(msg(format!("{}: corrupt", path.display())));
    };
    let d: Digest = manifest
        .parse()
        .map_err(|_| msg(format!("{}: corrupt", path.display())))?;
    let dir = data.join("cans").join(d.hex());
    if !dir.is_dir() {
        return Ok(None);
    }
    Ok(Some(cant_pack::install::open_installed(&dir)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_need_a_registry_host() {
        for yes in [
            "ghcr.io/cantainer/grep:3.11",
            "localhost:5000/grep:1",
            "localhost/grep",
            "registry.example.com/a/b@sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ] {
            assert!(is_reference(yes), "{yes}");
            assert!(parse(yes).is_ok(), "{yes}");
        }
        for no in [
            "grep",
            "./grep.can",
            "grep.can",
            "cants/x.toml",
            "/abs/x.can",
            "library/grep:1",
            "../x/y",
        ] {
            assert!(!is_reference(no), "{no}");
        }
        assert!(parse("ghcr.io/Bad/Name").is_err());
        let r = parse("localhost:5000/grep:1").expect("parse");
        assert!(is_local(r.resolve_registry()));
        assert!(!is_local("ghcr.io"));
    }

    #[test]
    fn refs_stay_inside_the_data_directory() {
        let data = Path::new("/data");
        let p = ref_path(data, &parse("ghcr.io/cantainer/grep:3.11").expect("parse"));
        assert_eq!(p, Path::new("/data/refs/ghcr.io/cantainer/grep/tag-3.11"));
        let p = ref_path(
            data,
            &parse("ghcr.io/a/b@sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad").expect("parse"),
        );
        assert!(p.starts_with("/data/refs/ghcr.io/a/b/"));
    }
}
