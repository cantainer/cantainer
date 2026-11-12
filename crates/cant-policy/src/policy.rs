//! The effective policy of a cant and attenuation (intersection) of policies.

use std::fmt;
use std::path::{Path, PathBuf};

use cant_manifest::EnvPattern;
use serde::{Deserialize, Serialize};

use crate::Access;

/// Why a grant exists. Shown by `--explain`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Declared in the manifest's `capabilities.fs`.
    Manifest,
    /// Declared in the manifest's `capabilities.exec`.
    ManifestExec,
    /// Powerbox: named by command-line argument number `index` (0-based, user args only).
    Argument {
        /// Position among the user's arguments.
        index: usize,
    },
    /// `--grant` on the `cant` command line.
    User,
    /// The cant's own executable.
    Executable,
    /// The ELF interpreter or a shared library of an executable.
    Library,
    /// Baseline runtime files every dynamically linked program needs.
    Runtime,
    /// Needed by a cant this one may run (`capabilities.cants`), or by `cant` itself.
    Cant {
        /// The cant's name (`cant` for the launcher itself).
        name: String,
    },
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Origin::Manifest => f.write_str("manifest"),
            Origin::ManifestExec => f.write_str("manifest exec"),
            Origin::Argument { index } => write!(f, "argument {}", index + 1),
            Origin::User => f.write_str("--grant"),
            Origin::Executable => f.write_str("executable"),
            Origin::Library => f.write_str("library"),
            Origin::Runtime => f.write_str("runtime"),
            Origin::Cant { name } => write!(f, "cant {name}"),
        }
    }
}

/// Access to one file or directory tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    /// Canonical absolute path.
    pub path: PathBuf,
    /// Rights on `path` and, for directories, everything beneath it.
    pub access: Access,
    /// Why the grant exists.
    pub origin: Origin,
    /// The file does not exist yet; the launcher creates it (empty) before applying rules.
    /// Only set for writable command-line files.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub create: bool,
}

/// Everything a cant may do.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Filesystem grants. Rights accumulate down the tree, as in Landlock.
    #[serde(default)]
    pub grants: Vec<Grant>,
    /// May open IP (non-Unix) sockets.
    #[serde(default)]
    pub network: bool,
    /// May open Unix domain sockets.
    #[serde(default)]
    pub unix_sockets: bool,
    /// May change permissions by path, to modes within `0775` (see `capabilities.chmod_by_path`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub chmod_by_path: bool,
    /// Environment variables that pass through.
    #[serde(default)]
    pub env: Vec<EnvPattern>,
}

impl Policy {
    /// The rights at `path`: the union of all grants on `path` or an ancestor.
    pub fn access_at(&self, path: &Path) -> Access {
        self.grants
            .iter()
            .filter(|g| path.starts_with(&g.path))
            .fold(Access::NONE, |acc, g| acc | g.access)
    }

    /// Whether `access` is allowed at `path`.
    pub fn permits(&self, path: &Path, access: Access) -> bool {
        self.access_at(path).contains(access)
    }

    /// Whether an environment variable passes through.
    pub fn passes_env(&self, name: &str) -> bool {
        self.env.iter().any(|p| p.matches(name))
    }

    /// Adds a grant, merging with an existing grant on the same path.
    pub fn add(&mut self, grant: Grant) {
        if grant.access.is_empty() {
            return;
        }
        if let Some(existing) = self.grants.iter_mut().find(|g| g.path == grant.path) {
            existing.access = existing.access | grant.access;
            existing.create |= grant.create;
        } else {
            self.grants.push(grant);
        }
    }

    /// Serializes for passing to a nested `cant` (see [`intersect`]).
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        // Paths that are not UTF-8 cannot be represented in TOML; dropping them only
        // makes the description narrower than reality, never wider.
        let mut clean = self.clone();
        clean.grants.retain(|g| g.path.to_str().is_some());
        toml::to_string(&clean)
    }

    /// Parses the output of [`Policy::to_toml`].
    pub fn from_toml(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }
}

/// Attenuation: the policy a child gets when a cant holding `parent` launches a cant
/// declaring `child`. Rights only shrink: for every path and right,
/// `intersect(p, c).permits(x, a) == p.permits(x, a) && c.permits(x, a)`.
///
/// Enforcement does not depend on this function: Landlock domains and seccomp filters stack
/// across `exec`, so the kernel already applies the intersection. `cant` uses this to explain
/// the effective policy and to refuse early with a clear message.
pub fn intersect(parent: &Policy, child: &Policy) -> Policy {
    let mut out = Policy {
        grants: Vec::new(),
        network: parent.network && child.network,
        unix_sockets: parent.unix_sockets && child.unix_sockets,
        chmod_by_path: parent.chmod_by_path && child.chmod_by_path,
        env: Vec::new(),
    };
    for c in &child.grants {
        for p in &parent.grants {
            let access = c.access & p.access;
            if access.is_empty() {
                continue;
            }
            // Of two comparable paths, the deeper one bounds the intersection.
            let path = if c.path.starts_with(&p.path) {
                &c.path
            } else if p.path.starts_with(&c.path) {
                &p.path
            } else {
                continue;
            };
            out.add(Grant {
                path: path.clone(),
                access,
                origin: c.origin.clone(),
                create: c.create && path == &c.path,
            });
        }
    }
    for c in &child.env {
        for p in &parent.env {
            if let Some(both) = c.intersect(p) {
                if !out.env.contains(&both) {
                    out.env.push(both);
                }
            }
        }
    }
    out
}

/// Child grants the parent does not fully allow (they will be denied by the kernel).
pub fn not_permitted_by<'a>(parent: &Policy, child: &'a Policy) -> Vec<&'a Grant> {
    child
        .grants
        .iter()
        .filter(|g| !parent.permits(&g.path, g.access))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn g(path: &str, access: Access) -> Grant {
        Grant {
            path: PathBuf::from(path),
            access,
            origin: Origin::Manifest,
            create: false,
        }
    }

    fn pat(s: &str) -> EnvPattern {
        EnvPattern::parse(s).expect("valid pattern")
    }

    #[test]
    fn rights_accumulate_down_the_tree() {
        let p = Policy {
            grants: vec![g("/a", Access::R), g("/a/b", Access::RW)],
            ..Policy::default()
        };
        assert!(p.permits(Path::new("/a/x"), Access::R));
        assert!(!p.permits(Path::new("/a/x"), Access::RW));
        assert!(p.permits(Path::new("/a/b/c"), Access::RW));
        assert!(
            !p.permits(Path::new("/ab"), Access::R),
            "component-wise prefix"
        );
        assert!(!p.permits(Path::new("/"), Access::R));
    }

    #[test]
    fn intersect_narrows_paths_and_rights() {
        let parent = Policy {
            grants: vec![g("/home/u/proj", Access::RW), g("/usr", Access::RX)],
            network: true,
            unix_sockets: false,
            chmod_by_path: true,
            env: vec![pat("LC_*"), pat("TERM")],
        };
        let child = Policy {
            grants: vec![
                g("/home/u/proj/notes.txt", Access::RW),
                g("/home/u", Access::R),
                g("/usr/bin/vim", Access::RX),
                g("/etc", Access::R),
            ],
            network: false,
            unix_sockets: true,
            chmod_by_path: true,
            env: vec![pat("LC_ALL"), pat("HOME"), pat("TERM")],
        };
        let eff = intersect(&parent, &child);
        let mut got: Vec<(String, String)> = eff
            .grants
            .iter()
            .map(|g| (g.path.display().to_string(), g.access.to_string()))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![
                ("/home/u/proj".into(), "r".into()),
                ("/home/u/proj/notes.txt".into(), "rw".into()),
                ("/usr/bin/vim".into(), "rx".into()),
            ]
        );
        assert!(!eff.network);
        assert!(!eff.unix_sockets);
        assert_eq!(eff.env, vec![pat("LC_ALL"), pat("TERM")]);
        let denied: Vec<_> = not_permitted_by(&parent, &child)
            .iter()
            .map(|g| g.path.display().to_string())
            .collect();
        assert_eq!(denied, vec!["/home/u", "/etc"]);
    }

    #[test]
    fn intersect_with_empty_parent_is_empty() {
        let child = Policy {
            grants: vec![g("/", Access::RW)],
            network: true,
            unix_sockets: true,
            chmod_by_path: true,
            env: vec![pat("TERM")],
        };
        let eff = intersect(&Policy::default(), &child);
        assert_eq!(eff, Policy::default());
    }

    #[test]
    fn toml_roundtrip() {
        let p = Policy {
            grants: vec![
                g("/a", Access::RX),
                Grant {
                    create: true,
                    origin: Origin::Argument { index: 2 },
                    ..g("/b", Access::RW)
                },
            ],
            network: true,
            unix_sockets: false,
            chmod_by_path: true,
            env: vec![pat("LC_*")],
        };
        let text = p.to_toml().expect("serialize");
        assert_eq!(Policy::from_toml(&text).expect("parse"), p);
    }

    // Paths drawn from a tiny tree so that ancestors and siblings collide often.
    fn arb_path() -> impl Strategy<Value = PathBuf> {
        proptest::collection::vec(prop_oneof!["a", "b", "c"], 0..4).prop_map(|parts| {
            let mut p = PathBuf::from("/");
            for part in parts {
                p.push(part);
            }
            p
        })
    }

    fn arb_access() -> impl Strategy<Value = Access> {
        (any::<bool>(), any::<bool>(), any::<bool>()).prop_map(|(read, write, exec)| Access {
            read,
            write,
            exec,
        })
    }

    fn arb_policy() -> impl Strategy<Value = Policy> {
        (
            proptest::collection::vec((arb_path(), arb_access()), 0..6),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(grants, network, unix_sockets)| {
                let mut p = Policy {
                    network,
                    unix_sockets,
                    ..Policy::default()
                };
                for (path, access) in grants {
                    p.add(Grant {
                        path,
                        access,
                        origin: Origin::Manifest,
                        create: false,
                    });
                }
                p
            })
    }

    proptest! {
        #[test]
        fn intersection_is_exact(parent in arb_policy(), child in arb_policy(),
                                 x in arb_path(), a in arb_access()) {
            let eff = intersect(&parent, &child);
            prop_assert_eq!(
                eff.permits(&x, a),
                parent.permits(&x, a) && child.permits(&x, a)
            );
            prop_assert_eq!(eff.network, parent.network && child.network);
        }

        #[test]
        fn intersection_is_commutative_in_effect(p in arb_policy(), c in arb_policy(),
                                                 x in arb_path(), a in arb_access()) {
            prop_assert_eq!(intersect(&p, &c).permits(&x, a), intersect(&c, &p).permits(&x, a));
        }
    }
}
