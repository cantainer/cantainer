//! Finding manifests: `cant run NAME` looks in the user's directory, then the system
//! directory, then the manifests built into `cant`.
//!
//! The built-in manifests live in `crates/cantainer/cants/` and are compiled into the binary,
//! so every installation (packages, Homebrew, `cargo install`, a bare binary) has them without
//! knowing where any data directory is. Files with the same name in the user or system
//! directory take precedence.

use std::fmt;
use std::path::{Path, PathBuf};

use cant_manifest::{Manifest, validate_name};

/// Manifests compiled into `cant`, as (name, TOML text). Sorted by name.
pub const BUILTIN: &[(&str, &str)] = &[
    ("cat", include_str!("../cants/cat.toml")),
    ("curl", include_str!("../cants/curl.toml")),
    ("curl-net", include_str!("../cants/curl-net.toml")),
    ("diff", include_str!("../cants/diff.toml")),
    ("find", include_str!("../cants/find.toml")),
    ("git", include_str!("../cants/git.toml")),
    ("grep", include_str!("../cants/grep.toml")),
    ("head", include_str!("../cants/head.toml")),
    ("jq", include_str!("../cants/jq.toml")),
    ("ls", include_str!("../cants/ls.toml")),
    ("rg", include_str!("../cants/rg.toml")),
    ("sed", include_str!("../cants/sed.toml")),
    ("tail", include_str!("../cants/tail.toml")),
    ("tree", include_str!("../cants/tree.toml")),
    ("vim", include_str!("../cants/vim.toml")),
    ("wc", include_str!("../cants/wc.toml")),
];

/// Directory for manifests an administrator installs for all users.
pub const SYSTEM_DIR: &str = "/etc/cantainer/cants";

/// Where a manifest came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A file: in a search directory, or given as a path.
    File(PathBuf),
    /// Compiled into `cant`.
    Builtin(&'static str),
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Source::File(p) => write!(f, "{}", p.display()),
            Source::Builtin(_) => f.write_str("built in"),
        }
    }
}

/// A manifest, its text and where it came from.
#[derive(Debug)]
pub struct Found {
    /// Where it came from.
    pub source: Source,
    /// The TOML text, as read.
    pub text: String,
    /// The parsed, validated manifest.
    pub manifest: Manifest,
}

/// The directories searched for `NAME.toml`, in order, before the built-in manifests.
#[derive(Debug, Clone)]
pub struct Catalog {
    /// Search directories, highest precedence first.
    pub dirs: Vec<PathBuf>,
}

/// One entry of `cant list`.
#[derive(Debug)]
pub struct Entry {
    /// The name `cant run` takes.
    pub name: String,
    /// Where `cant run NAME` would take it from.
    pub source: Source,
    /// The manifest's description, or why it is invalid.
    pub description: Result<String, String>,
}

impl Catalog {
    /// The standard search path: `$XDG_CONFIG_HOME/cantainer/cants` (or
    /// `~/.config/cantainer/cants`), then [`SYSTEM_DIR`].
    pub fn standard(home: &Path) -> Self {
        let config = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(c) if Path::new(&c).is_absolute() => PathBuf::from(c),
            _ => home.join(".config"),
        };
        Catalog {
            dirs: vec![
                config.join("cantainer").join("cants"),
                PathBuf::from(SYSTEM_DIR),
            ],
        }
    }

    /// Finds a manifest by name or path. A name containing `/` or ending in `.toml` is a path.
    pub fn find(&self, name: &str) -> Result<Found, String> {
        if name.contains('/') || name.ends_with(".toml") {
            return load_file(PathBuf::from(name));
        }
        validate_name(name)?;
        let file = format!("{name}.toml");
        if let Some(path) = self
            .dirs
            .iter()
            .map(|d| d.join(&file))
            .find(|p| p.is_file())
        {
            return load_file(path);
        }
        if let Some((builtin, text)) = BUILTIN.iter().find(|(n, _)| *n == name) {
            let manifest = Manifest::from_toml_str(text)
                .map_err(|e| format!("built-in manifest {builtin}: {e}"))?;
            return Ok(Found {
                source: Source::Builtin(builtin),
                text: (*text).to_owned(),
                manifest,
            });
        }
        let looked: Vec<String> = self.dirs.iter().map(|d| d.display().to_string()).collect();
        Err(format!(
            "no cant named `{name}` (looked in {} and the built-in cants; `cant list` shows them)",
            looked.join(", ")
        ))
    }

    /// Every name `cant run NAME` can find, with the manifest it would use.
    pub fn list(&self) -> Vec<Entry> {
        let mut entries: std::collections::BTreeMap<String, Entry> = Default::default();
        for dir in &self.dirs {
            let Ok(read) = std::fs::read_dir(dir) else {
                continue;
            };
            for path in read.filter_map(Result::ok).map(|e| e.path()) {
                if path.extension().is_none_or(|e| e != "toml") {
                    continue;
                }
                let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                if validate_name(name).is_err() || entries.contains_key(name) {
                    continue; // not runnable by name, or shadowed by an earlier directory
                }
                let description = Manifest::from_file(&path)
                    .map(|m| m.description.unwrap_or_default())
                    .map_err(|e| e.to_string().lines().next().unwrap_or("").to_owned());
                entries.insert(
                    name.to_owned(),
                    Entry {
                        name: name.to_owned(),
                        source: Source::File(path),
                        description,
                    },
                );
            }
        }
        for (name, text) in BUILTIN {
            entries.entry((*name).to_owned()).or_insert_with(|| Entry {
                name: (*name).to_owned(),
                source: Source::Builtin(name),
                description: Manifest::from_toml_str(text)
                    .map(|m| m.description.unwrap_or_default())
                    .map_err(|e| e.to_string()),
            });
        }
        entries.into_values().collect()
    }
}

fn load_file(path: PathBuf) -> Result<Found, String> {
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let manifest =
        Manifest::from_toml_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Found {
        source: Source::File(path),
        text,
        manifest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cants_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("cants")
    }

    #[test]
    fn every_file_in_cants_is_built_in() {
        let mut files: Vec<String> = std::fs::read_dir(cants_dir())
            .expect("cants dir")
            .filter_map(Result::ok)
            .filter_map(|e| {
                e.file_name()
                    .to_str()?
                    .strip_suffix(".toml")
                    .map(str::to_owned)
            })
            .collect();
        files.sort();
        let builtin: Vec<&str> = BUILTIN.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            files, builtin,
            "BUILTIN must list every cants/*.toml, sorted"
        );
    }

    #[test]
    fn built_in_manifests_are_valid_and_named_after_their_file() {
        for (name, text) in BUILTIN {
            let m = Manifest::from_toml_str(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(m.name, *name, "{name}.toml declares name = {:?}", m.name);
            assert!(m.description.is_some(), "{name}: add a description");
        }
    }

    #[test]
    fn directories_take_precedence_over_built_ins() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let user = tmp.path().join("user");
        let system = tmp.path().join("system");
        std::fs::create_dir_all(&user).expect("mkdir");
        std::fs::create_dir_all(&system).expect("mkdir");
        let custom = "manifest_version = 1\nname = \"cat\"\nversion = \"9.9.9\"\n\
                      description = \"mine\"\n[entrypoint]\npath = \"cat\"\n";
        std::fs::write(system.join("cat.toml"), custom).expect("write");
        let catalog = Catalog {
            dirs: vec![user.clone(), system.clone()],
        };

        let found = catalog.find("cat").expect("find");
        assert_eq!(found.source, Source::File(system.join("cat.toml")));
        assert_eq!(found.manifest.version, "9.9.9");

        std::fs::write(user.join("cat.toml"), custom.replace("9.9.9", "1.0.0")).expect("write");
        assert_eq!(catalog.find("cat").expect("find").manifest.version, "1.0.0");

        assert_eq!(
            catalog.find("git").expect("find").source,
            Source::Builtin("git")
        );

        let listed: Vec<(String, Source)> = catalog
            .list()
            .into_iter()
            .map(|e| (e.name, e.source))
            .collect();
        assert!(listed.contains(&("cat".into(), Source::File(user.join("cat.toml")))));
        assert!(listed.contains(&("git".into(), Source::Builtin("git"))));
    }

    #[test]
    fn unknown_names_and_bad_names_are_errors() {
        let catalog = Catalog { dirs: vec![] };
        let e = catalog.find("no-such-cant").expect_err("missing");
        assert!(e.contains("no cant named `no-such-cant`"), "{e}");
        assert!(catalog.find("../etc/passwd").is_err());
    }

    #[test]
    fn the_current_directory_is_not_searched() {
        // A checkout's own `examples/` or `cants/` must not decide what `cant run NAME` runs.
        let catalog = Catalog::standard(Path::new("/nonexistent-home"));
        assert!(
            catalog.dirs.iter().all(|d| d.is_absolute()),
            "{:?}",
            catalog.dirs
        );
    }
}
