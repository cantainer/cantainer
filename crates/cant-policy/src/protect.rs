//! Protected paths: credentials and persistence points that no grant may reach unless the
//! user names them explicitly with `--grant`.
//!
//! Landlock rules only *add* access; there is no "deny" rule. So a grant on a directory that
//! contains a protected path would expose it. `cant` therefore refuses such grants before
//! launch instead of trying to carve out exceptions.

use std::path::{Path, PathBuf};

use crate::Access;

/// Home-relative paths that may not be read or written.
pub const SECRET_HOME_PATHS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".config/gcloud",
    ".kube",
    ".docker",
    ".netrc",
    ".git-credentials",
    ".config/git/credentials",
    ".config/gh",
    ".password-store",
    ".local/share/keyrings",
    ".pki",
    ".mozilla",
    ".config/google-chrome",
    ".config/chromium",
    ".cargo/credentials",
    ".cargo/credentials.toml",
    ".npmrc",
    ".pypirc",
    ".gem/credentials",
    ".bash_history",
    ".zsh_history",
];

/// Home-relative paths that may be read but not written: they would let a cant
/// change its own (or another cant's) rights, or run code outside any sandbox later.
pub const READ_ONLY_HOME_PATHS: &[&str] = &[
    ".config/cantainer",
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".profile",
    ".zshrc",
    ".zprofile",
    ".zshenv",
    ".config/fish",
    ".config/autostart",
    ".config/systemd",
];

/// One protected path and the most access any implicit grant may have there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPath {
    /// Canonical path if it exists, otherwise the literal path.
    pub path: PathBuf,
    /// The most access allowed without an explicit `--grant`.
    pub max: Access,
}

/// The set of protected paths for one user.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Protected {
    /// All protected paths.
    pub paths: Vec<ProtectedPath>,
}

/// How a grant collides with a protected path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collision {
    /// The grant is the protected path.
    Is,
    /// The grant is inside the protected path.
    Inside,
    /// The grant is a directory containing the protected path.
    Contains,
}

impl Protected {
    /// The built-in list for a home directory.
    pub fn defaults(home: &Path) -> Self {
        let mut paths = Vec::new();
        for (list, max) in [
            (SECRET_HOME_PATHS, Access::NONE),
            (READ_ONLY_HOME_PATHS, Access::R),
        ] {
            for rel in list {
                let literal = home.join(rel);
                // Protect both the literal location and, if it is a symlink, its target.
                if let Ok(canonical) = std::fs::canonicalize(&literal) {
                    if canonical != literal {
                        paths.push(ProtectedPath {
                            path: canonical,
                            max,
                        });
                    }
                }
                paths.push(ProtectedPath { path: literal, max });
            }
        }
        Protected { paths }
    }

    /// The first protected path that `access` on `path` would violate.
    pub fn check(&self, path: &Path, access: Access) -> Option<(&ProtectedPath, Collision)> {
        self.paths.iter().find_map(|p| {
            if p.max.contains(access) {
                return None;
            }
            let collision = if path == p.path {
                Collision::Is
            } else if path.starts_with(&p.path) {
                Collision::Inside
            } else if p.path.starts_with(path) {
                Collision::Contains
            } else {
                return None;
            };
            Some((p, collision))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn protected() -> Protected {
        Protected::defaults(Path::new("/nonexistent-home"))
    }

    #[test]
    fn secrets_are_unreadable() {
        let p = protected();
        let (hit, how) = p
            .check(Path::new("/nonexistent-home/.ssh/id_rsa"), Access::R)
            .expect("protected");
        assert_eq!(hit.path, Path::new("/nonexistent-home/.ssh"));
        assert_eq!(how, Collision::Inside);
        assert_eq!(
            p.check(Path::new("/nonexistent-home/.ssh"), Access::R)
                .map(|x| x.1),
            Some(Collision::Is)
        );
    }

    #[test]
    fn ancestors_of_secrets_are_refused() {
        let p = protected();
        let (_, how) = p
            .check(Path::new("/nonexistent-home"), Access::R)
            .expect("home contains .ssh");
        assert_eq!(how, Collision::Contains);
        assert!(p.check(Path::new("/"), Access::R).is_some());
    }

    #[test]
    fn config_is_read_only() {
        let p = protected();
        let cfg = Path::new("/nonexistent-home/.config/cantainer/cants/x.toml");
        assert!(p.check(cfg, Access::R).is_none());
        assert!(p.check(cfg, Access::RW).is_some());
        assert!(
            p.check(Path::new("/nonexistent-home/.bashrc"), Access::RW)
                .is_some()
        );
    }

    #[test]
    fn unrelated_paths_are_fine() {
        let p = protected();
        for path in [
            "/nonexistent-home/proj/notes.txt",
            "/nonexistent-home/.sshx",
            "/usr/share",
            "/tmp/x",
        ] {
            assert!(p.check(Path::new(path), Access::RW).is_none(), "{path}");
        }
    }
}
