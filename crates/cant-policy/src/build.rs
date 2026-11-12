//! Building a policy from a manifest, a command line and the user's explicit grants.

use std::ffi::OsString;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cant_manifest::{Manifest, PathSpec};

use crate::protect::{Collision, Protected};
use crate::{Access, Grant, Origin, Policy, file_args};

/// Fixed directories searched for bare program names. The caller's `$PATH` is never used:
/// it is attacker-influenced in exactly the situations a sandbox is for.
pub const SYSTEM_BIN_DIRS: &[&str] = &[
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/local/sbin",
    "/usr/sbin",
    "/sbin",
];

/// Inputs that come from the environment of `cant` itself.
#[derive(Debug, Clone)]
pub struct Context {
    /// The user's home directory.
    pub home: PathBuf,
    /// The directory `cant` runs in (`$CWD` in manifests).
    pub cwd: PathBuf,
    /// Protected paths.
    pub protected: Protected,
}

impl Context {
    /// Context with the built-in protected paths.
    pub fn new(home: PathBuf, cwd: PathBuf) -> Self {
        let protected = Protected::defaults(&home);
        Context {
            home,
            cwd,
            protected,
        }
    }

    /// Shows a path relative to home (`~/...`) when possible.
    pub fn show(&self, path: &Path) -> String {
        display_path(path, &self.home)
    }
}

/// Shows a path relative to home (`~/...`) when possible.
pub fn display_path(path: &Path, home: &Path) -> String {
    if home != Path::new("/") {
        if let Ok(rest) = path.strip_prefix(home) {
            return if rest.as_os_str().is_empty() {
                "~".into()
            } else {
                format!("~/{}", rest.display())
            };
        }
    }
    path.display().to_string()
}

/// An explicit `--grant PATH[:ACCESS]` from the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserGrant {
    /// The path as typed (relative paths are relative to the working directory).
    pub path: PathBuf,
    /// Requested access.
    pub access: Access,
}

impl std::str::FromStr for UserGrant {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `PATH:rw`. A path that itself contains `:` can be granted as `PATH:r`.
        if let Some((path, access)) = s.rsplit_once(':') {
            if let Ok(access) = access.parse::<Access>() {
                if path.is_empty() {
                    return Err("empty path".into());
                }
                return Ok(UserGrant {
                    path: path.into(),
                    access,
                });
            }
        }
        if s.is_empty() {
            return Err("empty path".into());
        }
        Ok(UserGrant {
            path: s.into(),
            access: Access::R,
        })
    }
}

/// A manifest path that was not granted because it does not exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    /// The path that was looked for.
    pub path: PathBuf,
    /// Where it came from.
    pub origin: Origin,
}

/// The result of [`build`].
#[derive(Debug, Clone)]
pub struct Built {
    /// The policy, without the executable's libraries (the launcher adds those).
    pub policy: Policy,
    /// The executable to run, as found (may be a symlink; used for `argv[0]` and messages).
    pub program: PathBuf,
    /// The executable's canonical path.
    pub program_canonical: PathBuf,
    /// Executables granted by `capabilities.exec` (canonical paths; the launcher resolves
    /// their libraries).
    pub exec_targets: Vec<PathBuf>,
    /// Manifest paths that do not exist and were skipped.
    pub skipped: Vec<Skipped>,
    /// `[env] set`, with `$CWD` and `~` expanded.
    pub env_set: Vec<(String, std::ffi::OsString)>,
}

/// Why `cant` refused to build a policy. Messages are complete sentences without the
/// `cant:` prefix, which the CLI adds.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// A grant would reach a protected path.
    #[error("{cant} can't {verb} {shown} ({reason}){hint}")]
    Protected {
        /// Cant name.
        cant: String,
        /// "read", "write" or "execute".
        verb: &'static str,
        /// The requested path, for display.
        shown: String,
        /// Explanation.
        reason: String,
        /// Suggestion.
        hint: String,
    },
    /// The entrypoint or an exec target could not be found.
    #[error("{cant}: program `{name}` not found in {}", SYSTEM_BIN_DIRS.join(", "))]
    ProgramNotFound {
        /// Cant name.
        cant: String,
        /// Program name.
        name: String,
    },
    /// A path could not be inspected.
    #[error("{cant}: cannot use {shown}: {source}")]
    Io {
        /// Cant name.
        cant: String,
        /// The path, for display.
        shown: String,
        /// Underlying error.
        source: io::Error,
    },
    /// A writable file argument is a symlink that points nowhere.
    #[error(
        "{cant} can't write {shown} (it is a symlink to a file that does not exist; refusing to create it)"
    )]
    DanglingSymlink {
        /// Cant name.
        cant: String,
        /// The path, for display.
        shown: String,
    },
}

/// Finds a bare program name in [`SYSTEM_BIN_DIRS`].
pub fn find_program(name: &str) -> Option<PathBuf> {
    SYSTEM_BIN_DIRS.iter().find_map(|dir| {
        let candidate = Path::new(dir).join(name);
        let meta = std::fs::metadata(&candidate).ok()?;
        (meta.is_file() && meta.permissions().mode() & 0o111 != 0).then_some(candidate)
    })
}

struct Builder<'a> {
    manifest: &'a Manifest,
    ctx: &'a Context,
    unlocked: Vec<(PathBuf, Access)>,
    policy: Policy,
    skipped: Vec<Skipped>,
}

impl Builder<'_> {
    fn io_err(&self, path: &Path, source: io::Error) -> PolicyError {
        PolicyError::Io {
            cant: self.manifest.name.clone(),
            shown: self.ctx.show(path),
            source,
        }
    }

    /// Refuses grants that reach protected paths, unless the user unlocked them.
    fn check_protected(
        &self,
        path: &Path,
        access: Access,
        origin: &Origin,
    ) -> Result<(), PolicyError> {
        let unlocked = self
            .unlocked
            .iter()
            .any(|(u, ua)| path.starts_with(u) && ua.contains(access));
        if unlocked {
            return Ok(());
        }
        let Some((hit, how)) = self.ctx.protected.check(path, access) else {
            return Ok(());
        };
        let protected = self.ctx.show(&hit.path);
        let shown = self.ctx.show(path);
        let what = if hit.max.is_empty() {
            "protected"
        } else {
            "protected from writes"
        };
        let reason = match how {
            Collision::Is => what.to_string(),
            Collision::Inside => format!("{protected} is {what}"),
            Collision::Contains => format!("it contains {protected}, which is {what}"),
        };
        let reason = match origin {
            Origin::Manifest | Origin::ManifestExec if path == self.ctx.cwd => {
                format!("{reason}; the manifest grants the current directory")
            }
            Origin::Manifest | Origin::ManifestExec => format!("{reason}; granted by the manifest"),
            _ => reason,
        };
        let hint = match (origin, how) {
            (_, Collision::Contains)
                if matches!(origin, Origin::Manifest) && path == self.ctx.cwd =>
            {
                "; run it from a project directory instead".to_string()
            }
            (Origin::Argument { .. }, _) => format!(
                "; to allow it anyway: cant run --grant {shown}:{} {} ...",
                access, self.manifest.name
            ),
            _ => String::new(),
        };
        Err(PolicyError::Protected {
            cant: self.manifest.name.clone(),
            verb: access.verb(),
            shown,
            reason,
            hint,
        })
    }

    fn grant(
        &mut self,
        path: PathBuf,
        access: Access,
        origin: Origin,
        create: bool,
    ) -> Result<(), PolicyError> {
        self.check_protected(&path, access, &origin)?;
        self.policy.add(Grant {
            path,
            access,
            origin,
            create,
        });
        Ok(())
    }

    /// Grants a manifest path if it exists.
    fn grant_spec(&mut self, raw: &str, access: Access, origin: Origin) -> Result<(), PolicyError> {
        let spec = PathSpec::parse(raw, matches!(origin, Origin::ManifestExec)).map_err(|e| {
            self.io_err(
                Path::new(raw),
                io::Error::new(io::ErrorKind::InvalidInput, e),
            )
        })?;
        let path = match &spec {
            PathSpec::Bare(name) => match find_program(name) {
                Some(p) => p,
                None => {
                    self.skipped.push(Skipped {
                        path: PathBuf::from(name),
                        origin,
                    });
                    return Ok(());
                }
            },
            other => other.resolve(&self.ctx.home, &self.ctx.cwd),
        };
        match std::fs::canonicalize(&path) {
            Ok(canonical) => self.grant(canonical, access, origin, false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                self.skipped.push(Skipped { path, origin });
                Ok(())
            }
            Err(e) => Err(self.io_err(&path, e)),
        }
    }

    /// Grants a file named on the command line.
    fn grant_arg(
        &mut self,
        index: usize,
        value: &OsString,
        access: Access,
    ) -> Result<(), PolicyError> {
        let path = self.ctx.cwd.join(value);
        let origin = Origin::Argument { index };
        match std::fs::canonicalize(&path) {
            Ok(canonical) => self.grant(canonical, access, origin, false),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if !access.write {
                    // Nothing to grant; the program reports the missing file itself.
                    // A protected location is still refused, so the answer does not depend
                    // on whether the secret happens to exist.
                    let lexical = nearest_canonical(&path);
                    return self.check_protected(&lexical, access, &origin);
                }
                if std::fs::symlink_metadata(&path).is_ok() {
                    return Err(PolicyError::DanglingSymlink {
                        cant: self.manifest.name.clone(),
                        shown: self.ctx.show(&path),
                    });
                }
                // A writable file that does not exist yet: grant the exact name in the
                // (existing) parent directory; the launcher creates it empty.
                let (Some(parent), Some(name)) = (path.parent(), path.file_name()) else {
                    return Ok(());
                };
                match std::fs::canonicalize(parent) {
                    Ok(parent) => self.grant(parent.join(name), access, origin, true),
                    Err(_) => {
                        let lexical = nearest_canonical(&path);
                        self.check_protected(&lexical, access, &origin)
                    }
                }
            }
            Err(e) => Err(self.io_err(&path, e)),
        }
    }
}

/// Canonicalizes the longest existing ancestor of `path` and appends the rest unchanged.
/// Used to name paths that do not exist (yet) in protection checks.
fn nearest_canonical(path: &Path) -> PathBuf {
    let mut rest = Vec::new();
    let mut cur = path;
    loop {
        if let Ok(base) = std::fs::canonicalize(cur) {
            let mut out = base;
            for part in rest.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_os_string());
                cur = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

/// Builds the policy for running `manifest` with the user's `args`.
pub fn build(
    manifest: &Manifest,
    ctx: &Context,
    args: &[OsString],
    user_grants: &[UserGrant],
) -> Result<Built, PolicyError> {
    let mut b = Builder {
        manifest,
        ctx,
        unlocked: Vec::new(),
        policy: Policy {
            network: manifest.capabilities.network,
            unix_sockets: manifest.capabilities.unix_sockets,
            env: manifest.env_patterns(),
            grants: Vec::new(),
        },
        skipped: Vec::new(),
    };

    // 1. The user's explicit grants come first: they unlock protected paths.
    for ug in user_grants {
        let path = ctx.cwd.join(&ug.path);
        let canonical = std::fs::canonicalize(&path).map_err(|e| b.io_err(&path, e))?;
        b.unlocked.push((canonical.clone(), ug.access));
        b.policy.add(Grant {
            path: canonical,
            access: ug.access,
            origin: Origin::User,
            create: false,
        });
    }

    // 2. The executable.
    let (program, program_canonical) = resolve_entrypoint(manifest, &ctx.home)?;
    b.grant(
        program_canonical.clone(),
        Access::RX,
        Origin::Executable,
        false,
    )?;

    // 3. Manifest paths.
    for raw in &manifest.capabilities.fs.ro {
        b.grant_spec(raw, Access::R, Origin::Manifest)?;
    }
    for raw in &manifest.capabilities.fs.rw {
        b.grant_spec(raw, Access::RW, Origin::Manifest)?;
    }
    let before = b.policy.grants.len();
    for raw in &manifest.capabilities.exec {
        b.grant_spec(raw, Access::RX, Origin::ManifestExec)?;
    }
    let exec_targets = b.policy.grants[before..]
        .iter()
        .filter(|g| g.path.is_file())
        .map(|g| g.path.clone())
        .collect();

    // 4. Powerbox: files named on the command line.
    for fa in file_args(&manifest.args, args) {
        b.grant_arg(fa.index, &fa.value, fa.access)?;
    }

    // 5. Fixed environment variables.
    let env_set = manifest
        .env
        .set
        .iter()
        .map(|(name, value)| {
            let value = if value.starts_with("$CWD") || value.starts_with('~') {
                match PathSpec::parse(value, false) {
                    Ok(spec) => spec.resolve(&ctx.home, &ctx.cwd).into_os_string(),
                    Err(_) => value.into(), // unreachable for a validated manifest
                }
            } else {
                value.into()
            };
            (name.clone(), value)
        })
        .collect();

    Ok(Built {
        policy: b.policy,
        program,
        program_canonical,
        exec_targets,
        skipped: b.skipped,
        env_set,
    })
}

/// Finds the entrypoint: (path as found, canonical path).
pub fn resolve_entrypoint(
    manifest: &Manifest,
    home: &Path,
) -> Result<(PathBuf, PathBuf), PolicyError> {
    let cant = manifest.name.clone();
    let raw = &manifest.entrypoint.path;
    let program = if raw.starts_with('/') {
        PathBuf::from(raw)
    } else if let Some(rest) = raw.strip_prefix("~/") {
        home.join(rest)
    } else {
        find_program(raw).ok_or_else(|| PolicyError::ProgramNotFound {
            cant: cant.clone(),
            name: raw.clone(),
        })?
    };
    let canonical = std::fs::canonicalize(&program).map_err(|source| match source.kind() {
        io::ErrorKind::NotFound => PolicyError::ProgramNotFound {
            cant: cant.clone(),
            name: raw.clone(),
        },
        _ => PolicyError::Io {
            cant: cant.clone(),
            shown: program.display().to_string(),
            source,
        },
    })?;
    Ok((program, canonical))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAT: &str = r#"
manifest_version = 1
name = "cat"
version = "0.1.0"
[entrypoint]
path = "cat"
[args]
operands = "r"
"#;

    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        work: PathBuf,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canonical");
        let home = root.join("home");
        let work = home.join("proj");
        std::fs::create_dir_all(home.join(".ssh")).expect("mkdir");
        std::fs::create_dir_all(&work).expect("mkdir");
        std::fs::write(home.join(".ssh/id_rsa"), "secret").expect("write");
        std::fs::write(work.join("notes.txt"), "hello").expect("write");
        Fixture {
            _dir: dir,
            home,
            work,
        }
    }

    fn run(m: &str, f: &Fixture, args: &[&str], grants: &[&str]) -> Result<Built, PolicyError> {
        let manifest = Manifest::from_toml_str(m).expect("manifest");
        let ctx = Context::new(f.home.clone(), f.work.clone());
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let grants: Vec<UserGrant> = grants.iter().map(|g| g.parse().expect("grant")).collect();
        build(&manifest, &ctx, &args, &grants)
    }

    #[test]
    fn powerbox_grants_named_file() {
        let f = fixture();
        let built = run(CAT, &f, &["notes.txt"], &[]).expect("ok");
        let notes = f.work.join("notes.txt");
        assert!(built.policy.permits(&notes, Access::R));
        assert!(!built.policy.permits(&notes, Access::RW));
        assert!(!built.policy.permits(&f.work.join("other.txt"), Access::R));
    }

    #[test]
    fn protected_file_is_refused_with_hint() {
        let f = fixture();
        let err = run(CAT, &f, &["../.ssh/id_rsa"], &[]).expect_err("refused");
        let msg = err.to_string();
        assert!(
            msg.starts_with("cat can't read ~/.ssh/id_rsa (~/.ssh is protected"),
            "{msg}"
        );
        assert!(msg.contains("--grant ~/.ssh/id_rsa:r"), "{msg}");
    }

    #[test]
    fn missing_protected_file_is_still_refused() {
        let f = fixture();
        let err = run(CAT, &f, &["../.ssh/nope"], &[]).expect_err("refused");
        assert!(err.to_string().contains("~/.ssh is protected"), "{err}");
        let err = run(CAT, &f, &["../.aws/credentials"], &[]).expect_err("refused");
        assert!(err.to_string().contains("~/.aws is protected"), "{err}");
        // A missing, unprotected file is simply not granted.
        assert!(run(CAT, &f, &["missing.txt"], &[]).is_ok());
    }

    #[test]
    fn symlink_to_protected_file_is_refused() {
        let f = fixture();
        std::os::unix::fs::symlink(f.home.join(".ssh/id_rsa"), f.work.join("innocent"))
            .expect("symlink");
        let err = run(CAT, &f, &["innocent"], &[]).expect_err("refused");
        assert!(err.to_string().contains("~/.ssh/id_rsa"), "{err}");
    }

    #[test]
    fn explicit_grant_unlocks() {
        let f = fixture();
        let key = f.home.join(".ssh/id_rsa");
        let key_s = key.to_str().expect("utf8");
        let built = run(CAT, &f, &[key_s], &[key_s]).expect("unlocked");
        assert!(built.policy.permits(&key, Access::R));
        // Unlocking read does not unlock write.
        let vim = CAT.replace(r#"operands = "r""#, r#"operands = "rw""#);
        assert!(run(&vim, &f, &[key_s], &[key_s]).is_err());
    }

    #[test]
    fn cwd_grant_containing_secrets_is_refused() {
        let f = fixture();
        let m = format!("{CAT}\n[capabilities]\nfs.rw = [\"$CWD\"]\n");
        let manifest = Manifest::from_toml_str(&m).expect("manifest");
        let ctx = Context::new(f.home.clone(), f.home.clone());
        let err = build(&manifest, &ctx, &[], &[]).expect_err("home contains .ssh");
        let msg = err.to_string();
        assert!(msg.contains("it contains ~/.ssh"), "{msg}");
        assert!(msg.contains("run it from a project directory"), "{msg}");
        // From the project directory it is fine.
        assert!(run(&m, &f, &[], &[]).is_ok());
    }

    #[test]
    fn missing_writable_file_is_created_by_name_only() {
        let f = fixture();
        let vim = CAT.replace(r#"operands = "r""#, r#"operands = "rw""#);
        let built = run(&vim, &f, &["new.txt"], &[]).expect("ok");
        let g = built
            .policy
            .grants
            .iter()
            .find(|g| g.origin == Origin::Argument { index: 0 })
            .expect("grant");
        assert_eq!(g.path, f.work.join("new.txt"));
        assert!(g.create);
        assert!(!built.policy.permits(&f.work.join("other.txt"), Access::R));
    }

    #[test]
    fn dangling_symlink_is_refused() {
        let f = fixture();
        std::os::unix::fs::symlink(f.home.join(".ssh/new_key"), f.work.join("dangle"))
            .expect("symlink");
        let vim = CAT.replace(r#"operands = "r""#, r#"operands = "rw""#);
        let err = run(&vim, &f, &["dangle"], &[]).expect_err("refused");
        assert!(matches!(err, PolicyError::DanglingSymlink { .. }), "{err}");
    }

    #[test]
    fn missing_manifest_paths_are_skipped() {
        let f = fixture();
        let m = format!("{CAT}\n[capabilities]\nfs.ro = [\"~/.vimrc\", \"/usr\"]\n");
        let built = run(&m, &f, &[], &[]).expect("ok");
        assert_eq!(built.skipped.len(), 1);
        assert_eq!(built.skipped[0].path, f.home.join(".vimrc"));
        assert!(built.policy.permits(Path::new("/usr/bin"), Access::R));
    }

    #[test]
    fn user_grant_parsing() {
        let g: UserGrant = "notes.txt:rw".parse().expect("ok");
        assert_eq!(g.access, Access::RW);
        let g: UserGrant = "a:b".parse().expect("ok");
        assert_eq!((g.path.to_str(), g.access), (Some("a:b"), Access::R));
        assert!(":rw".parse::<UserGrant>().is_err());
    }

    #[test]
    fn display_paths() {
        let home = Path::new("/home/u");
        assert_eq!(display_path(Path::new("/home/u/.ssh"), home), "~/.ssh");
        assert_eq!(display_path(Path::new("/home/u"), home), "~");
        assert_eq!(display_path(Path::new("/home/uu"), home), "/home/uu");
    }
}
