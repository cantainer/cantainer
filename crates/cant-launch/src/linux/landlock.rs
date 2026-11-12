//! Landlock: deny-by-default filesystem (and TCP) access, then allow the policy's grants.

use std::os::unix::fs::FileTypeExt;

use cant_policy::{Access, Policy};
use landlock::{
    ABI, Access as _, AccessFs, AccessNet, BitFlags, LandlockStatus, PathBeneath, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope,
};

use crate::LaunchError;

/// Opens `path` with `O_PATH`, for use as the parent of a Landlock rule.
///
/// We don't use `landlock::PathFd`: it opens through `std::fs::OpenOptions`, and on musl
/// targets std strips `O_PATH` from custom flags (musl's `O_ACCMODE` includes `O_SEARCH`,
/// which equals `O_PATH`). The path is then opened for real: `/dev/tty` without a controlling
/// terminal fails with `ENXIO`, a FIFO blocks, an execute-only file fails. rustix issues the
/// `open` system call directly, so `O_PATH` is kept on every libc.
fn path_fd(path: &std::path::Path) -> std::io::Result<rustix::fd::OwnedFd> {
    use rustix::fs::{Mode, OFlags};
    rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).map_err(Into::into)
}

/// The newest Landlock ABI this build knows. Rights from newer ABIs than the running kernel
/// supports are dropped (best effort); [`MIN_ABI`] is enforced separately.
const TARGET_ABI: ABI = ABI::V9;

/// Below ABI 3, `truncate(2)` is not controlled, so a read-only grant would not stop a cant
/// from emptying a file. We refuse to run rather than pretend.
pub const MIN_ABI: i32 = 3;

/// What the kernel actually enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Enforced {
    /// The Landlock ABI used (the kernel's, capped at what this build knows).
    pub abi: i32,
    /// Whether every requested right was enforced.
    pub fully: bool,
}

fn abi_number(status: LandlockStatus) -> Option<i32> {
    match status {
        LandlockStatus::Available { effective_abi, .. } => Some(effective_abi as i32),
        LandlockStatus::NotEnabled | LandlockStatus::NotImplemented => None,
    }
}

fn err(context: &str, e: impl std::fmt::Display) -> LaunchError {
    LaunchError::Landlock(format!("{context}: {e}"))
}

/// Maps coarse rights onto Landlock rights for one path.
fn landlock_access(access: Access, is_dir: bool, is_char_device: bool) -> BitFlags<AccessFs> {
    let mut a = BitFlags::<AccessFs>::EMPTY;
    if access.read {
        a |= AccessFs::ReadFile;
        if is_dir {
            a |= AccessFs::ReadDir;
        }
    }
    if access.write {
        a |= AccessFs::WriteFile | AccessFs::Truncate;
        if is_dir {
            a |= AccessFs::RemoveFile
                | AccessFs::RemoveDir
                | AccessFs::MakeReg
                | AccessFs::MakeDir
                | AccessFs::MakeSym
                | AccessFs::MakeFifo
                | AccessFs::MakeSock
                | AccessFs::Refer;
        }
    }
    if access.exec {
        a |= AccessFs::Execute;
    }
    if is_char_device && (access.read || access.write) {
        a |= AccessFs::IoctlDev;
    }
    a
}

/// Restricts the calling process to `policy`. Irreversible; inherited across `exec`.
pub fn restrict(policy: &Policy) -> Result<Enforced, LaunchError> {
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(TARGET_ABI))
        .map_err(|e| err("filesystem rights", e))?;
    if !policy.network {
        ruleset = ruleset
            .handle_access(AccessNet::from_all(TARGET_ABI))
            .map_err(|e| err("network rights", e))?;
    }
    let mut scopes: BitFlags<Scope> = Scope::Signal.into();
    if !policy.unix_sockets {
        scopes |= Scope::AbstractUnixSocket;
    }
    let mut created = ruleset
        .scope(scopes)
        .map_err(|e| err("scopes", e))?
        .create()
        .map_err(|e| err("create ruleset", e))?;

    for grant in &policy.grants {
        let meta = std::fs::metadata(&grant.path)
            .map_err(|e| err(&format!("grant {}", grant.path.display()), e))?;
        let access = landlock_access(
            grant.access,
            meta.is_dir(),
            meta.file_type().is_char_device(),
        );
        if access.is_empty() {
            continue;
        }
        let fd =
            path_fd(&grant.path).map_err(|e| err(&format!("open {}", grant.path.display()), e))?;
        created = created
            .add_rule(PathBeneath::new(fd, access))
            .map_err(|e| err(&format!("rule for {}", grant.path.display()), e))?;
    }
    if policy.unix_sockets {
        // ABI 9+: connecting to pathname Unix sockets is a filesystem right.
        let fd = path_fd(std::path::Path::new("/")).map_err(|e| err("open /", e))?;
        created = created
            .add_rule(PathBeneath::new(fd, AccessFs::ResolveUnix))
            .map_err(|e| err("unix socket rule", e))?;
    }

    let status = created
        .restrict_self()
        .map_err(|e| err("restrict_self", e))?;
    let fully = status.ruleset == RulesetStatus::FullyEnforced;
    let abi = match (&status.ruleset, abi_number(status.landlock)) {
        (RulesetStatus::NotEnforced, _) | (_, None) => {
            return Err(LaunchError::LandlockUnavailable);
        }
        (_, Some(abi)) => abi,
    };
    if abi < MIN_ABI {
        return Err(LaunchError::LandlockTooOld { abi });
    }
    Ok(Enforced { abi, fully })
}

/// Reports the kernel's Landlock ABI by applying a no-op ruleset to the calling process
/// (it handles only `Execute` and then allows it everywhere). The `landlock` crate has no
/// other public way to ask. Call this only from a short-lived process.
pub fn probe_abi() -> Option<i32> {
    let ruleset = Ruleset::default()
        .handle_access(AccessFs::Execute)
        .ok()?
        .create()
        .ok()?;
    let fd = path_fd(std::path::Path::new("/")).ok()?;
    let status = ruleset
        .add_rule(PathBeneath::new(fd, AccessFs::Execute))
        .ok()?
        .restrict_self()
        .ok()?;
    abi_number(status.landlock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_fd_does_not_open_the_file() {
        // With O_PATH, opening /dev/tty succeeds even without a controlling terminal, and a
        // FIFO does not block.
        assert!(path_fd(std::path::Path::new("/dev/tty")).is_ok());
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("fifo");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .expect("mkfifo");
        assert!(path_fd(&fifo).is_ok());
    }

    #[test]
    fn access_mapping() {
        let f = landlock_access(Access::R, false, false);
        assert_eq!(f, AccessFs::ReadFile);
        let d = landlock_access(Access::RW, true, false);
        assert!(d.contains(AccessFs::ReadDir | AccessFs::MakeReg | AccessFs::Refer));
        assert!(!d.contains(AccessFs::MakeChar), "never device creation");
        assert!(!d.contains(AccessFs::Execute));
        let x = landlock_access(Access::RX, false, false);
        assert_eq!(x, AccessFs::ReadFile | AccessFs::Execute);
        let tty = landlock_access(Access::RW, false, true);
        assert!(tty.contains(AccessFs::IoctlDev));
        assert!(!landlock_access(Access::RW, false, false).contains(AccessFs::IoctlDev));
    }
}
