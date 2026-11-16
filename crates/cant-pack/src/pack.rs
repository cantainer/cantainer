//! `cant pack`: turn an installed program and its manifest into a can.
//!
//! The can's root mirrors the packing machine's paths: the program where it was found, its
//! ELF interpreter at the path written in the program (`lib64/ld-linux-x86-64.so.2`), each
//! shared library where its name was found (so the loader finds it by that name), and the
//! `[pack] include` trees. Symlinks on the host are followed: the can holds regular files.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cant_manifest::{CAN_MANIFEST_VERSION, Manifest, PathSpec};

use crate::layout::{
    self, ARTIFACT_TYPE, CONFIG_MEDIA_TYPE, Descriptor, FILE_MEDIA_TYPE, FORMAT_ANNOTATION,
    INDEX_MEDIA_TYPE, ImageIndex, ImageManifest, MANIFEST_MEDIA_TYPE, REF_ANNOTATION,
    SBOM_MEDIA_TYPE,
};
use crate::tree::{self, Entry, Entrypoint, Kind, Limits, Tree};
use crate::{Error, glob, sbom, timestamp};

/// Most files walked in one `include` tree, so a typo like `include = ["/"]` stops early.
const MAX_INCLUDED: usize = 50_000;

/// What `cant pack` produced.
#[derive(Debug)]
pub struct Packed {
    pub dir: PathBuf,
    pub files: usize,
    pub bytes: u64,
    pub manifest_digest: String,
    /// Things the publisher should know (skipped special files, ...).
    pub notes: Vec<String>,
}

/// One file of the can and where it comes from.
#[derive(Debug, Clone)]
struct Source {
    host: PathBuf,
    mode: &'static str,
}

fn rel(path: &Path) -> Result<String, Error> {
    let s = path
        .to_str()
        .ok_or_else(|| Error::Invalid(vec![format!("{}: not UTF-8", path.display())]))?;
    let r = s.trim_start_matches('/');
    if r.is_empty() || !path.is_absolute() {
        return Err(Error::Invalid(vec![format!(
            "{s}: not an absolute file path"
        )]));
    }
    Ok(r.to_string())
}

struct Files {
    map: BTreeMap<String, Source>,
    exclude: Vec<String>,
    notes: Vec<String>,
}

impl Files {
    fn add(&mut self, at: &Path, host: &Path, mode: &'static str) -> Result<(), Error> {
        let r = rel(at)?;
        if self.exclude.iter().any(|p| glob::matches(p, &r)) {
            return Ok(());
        }
        let host = std::fs::canonicalize(host).map_err(|e| Error::Io {
            path: host.to_path_buf(),
            source: e,
        })?;
        if let Some(existing) = self.map.get(&r) {
            if existing.host != host {
                return Err(Error::Invalid(vec![format!(
                    "{r} would come from both {} and {}",
                    existing.host.display(),
                    host.display()
                )]));
            }
            return Ok(());
        }
        self.map.insert(r, Source { host, mode });
        Ok(())
    }

    /// The program's or a library's closure.
    fn closure(&mut self, elf: &Path) -> Result<Option<(String, Vec<String>)>, Error> {
        let r =
            cant_launch::resolve_libraries(elf).map_err(|e| Error::Invalid(vec![e.to_string()]))?;
        if !r.missing.is_empty() {
            return Err(Error::Invalid(vec![format!(
                "{} needs libraries that weren't found: {}",
                elf.display(),
                r.missing.join(", ")
            )]));
        }
        let mut dirs: Vec<String> = Vec::new();
        for (found, canonical) in &r.found {
            self.add(found, canonical, "0644")?;
            if let Some(parent) = found.parent() {
                let d = rel(parent)?;
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
        }
        match (&r.interpreter_literal, &r.interpreter) {
            (Some(literal), Some(canonical)) => {
                self.add(literal, canonical, "0755")?;
                Ok(Some((rel(literal)?, dirs)))
            }
            _ => Ok(None),
        }
    }

    /// Everything under `path`, following symlinks; ELF files' libraries too if `elf`.
    fn include(&mut self, path: &Path, elf: bool, budget: &mut usize) -> Result<(), Error> {
        let meta = std::fs::metadata(path).map_err(|e| Error::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        if meta.is_dir() {
            let mut names: Vec<_> = std::fs::read_dir(path)
                .map_err(|e| Error::Io {
                    path: path.to_path_buf(),
                    source: e,
                })?
                .filter_map(Result::ok)
                .map(|e| e.file_name())
                .collect();
            names.sort();
            for n in names {
                self.include(&path.join(n), elf, budget)?;
            }
            return Ok(());
        }
        if !meta.is_file() {
            self.notes
                .push(format!("skipped {} (not a regular file)", path.display()));
            return Ok(());
        }
        if *budget == 0 {
            return Err(Error::Invalid(vec![format!(
                "more than {MAX_INCLUDED} files to include; narrow [pack] include"
            )]));
        }
        *budget -= 1;
        let executable = meta.permissions().mode() & 0o111 != 0;
        self.add(path, path, if executable { "0755" } else { "0644" })?;
        if elf && is_elf(path) {
            // Best effort: helpers with missing libraries are noted, not fatal.
            if let Err(e) = self.closure(path) {
                self.notes.push(e.to_string());
            }
        }
        Ok(())
    }
}

fn is_elf(path: &Path) -> bool {
    use std::io::Read;
    let mut magic = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && magic == *b"\x7fELF"
}

/// Packs `manifest` (version 1 or 2, with a host entrypoint) into a new layout directory.
pub fn pack(manifest: &Manifest, home: &Path, out: &Path) -> Result<Packed, Error> {
    if manifest.entrypoint.path.starts_with("$CAN") {
        return Err(Error::Invalid(vec![format!(
            "{} is already a can's manifest (entrypoint {})",
            manifest.name, manifest.entrypoint.path
        )]));
    }
    let (program, canonical) = cant_policy::resolve_entrypoint(manifest, home, None)
        .map_err(|e| Error::Invalid(vec![e.to_string()]))?;
    let pack = manifest.pack.clone().unwrap_or_default();
    let mut files = Files {
        map: BTreeMap::new(),
        exclude: pack.exclude.clone(),
        notes: Vec::new(),
    };
    files.add(&program, &canonical, "0755")?;
    let program_rel = rel(&program)?;
    let launch = files.closure(&canonical)?;
    let mut budget = MAX_INCLUDED;
    for raw in &pack.include {
        files.include(
            Path::new(raw),
            pack.elf_roots.iter().any(|r| raw.starts_with(r.as_str())),
            &mut budget,
        )?;
    }
    for raw in &pack.elf_roots {
        if !pack.include.iter().any(|i| raw.starts_with(i.as_str())) {
            files.include(Path::new(raw), true, &mut budget)?;
        }
    }

    // The tree: directories for every parent, then the files.
    let writer = layout::Writer::create(out)?;
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    let mut layers: BTreeMap<String, Descriptor> = BTreeMap::new();
    let mut shipped: Vec<(String, PathBuf, String)> = Vec::new();
    let mut bytes = 0u64;
    for (path, src) in &files.map {
        let mut parent = path.as_str();
        while let Some((p, _)) = parent.rsplit_once('/') {
            entries.entry(p.to_string()).or_insert_with(|| Entry {
                path: p.to_string(),
                kind: Kind::Dir,
                mode: Some("0755".into()),
                size: None,
                digest: None,
                target: None,
                bundle: None,
            });
            parent = p;
        }
        let desc = writer.put_file(FILE_MEDIA_TYPE, &src.host)?;
        bytes += desc.size;
        shipped.push((path.clone(), src.host.clone(), desc.digest.clone()));
        entries.insert(
            path.clone(),
            Entry {
                path: path.clone(),
                kind: Kind::File,
                mode: Some(src.mode.into()),
                size: Some(desc.size),
                digest: Some(desc.digest.clone()),
                target: None,
                bundle: None,
            },
        );
        layers.entry(desc.digest.clone()).or_insert(desc);
    }
    let (loader, library_path) = match launch {
        Some((loader, dirs)) => (Some(loader), dirs),
        None => (None, Vec::new()),
    };
    let tree = Tree {
        version: 1,
        entries: entries.into_values().collect(),
        entrypoint: Entrypoint {
            path: program_rel.clone(),
            loader,
            library_path,
        },
    };
    tree.validate(&Limits::default()).map_err(Error::Invalid)?;

    // The can's manifest: version 2, entrypoint inside the can.
    let mut can_manifest = manifest.clone();
    can_manifest.manifest_version = CAN_MANIFEST_VERSION;
    can_manifest.entrypoint.path = format!("$CAN/{program_rel}");
    let config_text =
        toml::to_string(&can_manifest).map_err(|e| Error::Invalid(vec![e.to_string()]))?;
    Manifest::from_toml_str(&config_text).map_err(|e| Error::Invalid(vec![e.to_string()]))?;
    // `$CAN` paths in fs.ro/exec must exist in the can, or they'd silently grant nothing.
    let in_tree = |raw: &str| {
        let rest = raw.trim_start_matches("$CAN").trim_start_matches('/');
        rest.is_empty() || tree.entries.iter().any(|e| e.path == rest)
    };
    for raw in can_manifest
        .capabilities
        .fs
        .ro
        .iter()
        .chain(&can_manifest.capabilities.exec)
    {
        if matches!(PathSpec::parse(raw, true), Ok(PathSpec::Can(_))) && !in_tree(raw) {
            files
                .notes
                .push(format!("{raw} is not in the can; add it to [pack] include"));
        }
    }

    let created = timestamp();
    let shipped_refs: Vec<sbom::Shipped<'_>> = shipped
        .iter()
        .map(|(p, h, d)| sbom::Shipped {
            path: p,
            host: h,
            digest: d,
        })
        .collect();
    let sbom = sbom::build(&manifest.name, &manifest.version, &shipped_refs, &created);

    let tree_desc = writer.put_json(tree::MEDIA_TYPE, &tree)?;
    let sbom_desc = writer.put_json(SBOM_MEDIA_TYPE, &sbom)?;
    let config_desc = writer.put_bytes(CONFIG_MEDIA_TYPE, config_text.as_bytes())?;
    let mut all_layers = vec![tree_desc, sbom_desc];
    all_layers.extend(layers.into_values());
    let mut annotations = BTreeMap::new();
    annotations.insert(FORMAT_ANNOTATION.to_string(), "1".to_string());
    annotations.insert(
        "org.opencontainers.image.title".into(),
        manifest.name.clone(),
    );
    annotations.insert(
        "org.opencontainers.image.version".into(),
        manifest.version.clone(),
    );
    annotations.insert("org.opencontainers.image.created".into(), created);
    let image = ImageManifest {
        schema_version: 2,
        media_type: MANIFEST_MEDIA_TYPE.into(),
        artifact_type: Some(ARTIFACT_TYPE.into()),
        config: config_desc,
        layers: all_layers,
        annotations,
    };
    let mut manifest_desc = writer.put_json(MANIFEST_MEDIA_TYPE, &image)?;
    manifest_desc.platform = Some(layout::this_platform());
    manifest_desc.artifact_type = Some(ARTIFACT_TYPE.into());
    let manifest_digest = manifest_desc.digest.clone();
    let index = ImageIndex {
        schema_version: 2,
        media_type: INDEX_MEDIA_TYPE.into(),
        artifact_type: Some(ARTIFACT_TYPE.into()),
        manifests: vec![manifest_desc],
        annotations: BTreeMap::new(),
    };
    let mut index_desc = writer.put_json(INDEX_MEDIA_TYPE, &index)?;
    index_desc.artifact_type = Some(ARTIFACT_TYPE.into());
    index_desc.annotations.insert(
        REF_ANNOTATION.into(),
        format!("{}:{}", manifest.name, manifest.version),
    );
    writer.finish(index_desc)?;

    Ok(Packed {
        dir: out.to_path_buf(),
        files: files.map.len(),
        bytes,
        manifest_digest,
        notes: files.notes,
    })
}
