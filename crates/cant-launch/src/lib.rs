//! Sandbox setup and exec for Cantainer.
//!
//! [`plan`] completes a policy with what the executable needs to start (its ELF interpreter,
//! shared libraries and a small runtime base), filters the environment and builds argv.
//! [`exec`] then makes the kernel enforce the plan and replaces the current process with the
//! program:
//!
//! 1. create writable command-line files that do not exist yet (so they have an inode),
//! 2. Landlock: deny by default, allow each grant (also sets `no_new_privs`),
//! 3. seccomp: baseline deny list plus the socket families the policy does not allow,
//! 4. `execve`.
//!
//! There is no supervisor process: exit status, signals and the terminal belong to the
//! program, exactly as if it had been run directly. Restrictions are inherited by everything
//! it starts and cannot be lifted.
//!
//! Linux only. On other systems every entry point returns [`LaunchError::Unsupported`], so the
//! workspace still builds on macOS for editing.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::PathBuf;

use cant_policy::Policy;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
pub use linux::elf::{ElfError, Resolved, resolve as resolve_libraries};
#[cfg(target_os = "linux")]
pub use linux::landlock::MIN_ABI;

/// Name of the environment variable carrying the effective policy into a cant, so that a
/// nested `cant` can explain and pre-check attenuation. It is informational: the kernel
/// enforces the real restrictions, and a forged value cannot widen them.
pub const POLICY_ENV: &str = "CANT_POLICY";

/// Files every dynamically linked program may need to read.
pub const RUNTIME_READ: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    "/etc/localtime",
    "/usr/share/zoneinfo",
    "/usr/lib/locale",
    "/usr/share/locale",
    "/etc/locale.alias",
    "/usr/share/terminfo",
    "/usr/lib/terminfo",
    "/lib/terminfo",
    "/etc/terminfo",
    "/dev/zero",
    "/dev/urandom",
    "/dev/random",
];

/// Devices every program may read and write.
pub const RUNTIME_READ_WRITE: &[&str] = &["/dev/null", "/dev/full", "/dev/tty"];

/// Everything needed to start a cant.
#[derive(Debug, Clone)]
pub struct Plan {
    /// Cant name, for messages.
    pub cant: String,
    /// Canonical path of the executable.
    pub program: PathBuf,
    /// `argv[0]` (the program's name as found, e.g. `vim` for `/usr/bin/vim.basic`).
    pub argv0: OsString,
    /// Arguments after `argv[0]`: the manifest's fixed arguments, then the user's.
    pub args: Vec<OsString>,
    /// The complete environment of the program.
    pub env: Vec<(OsString, OsString)>,
    /// The policy to enforce (this cant's own layer).
    pub policy: Policy,
    /// The policy in effect after attenuation by an enclosing cant (equal to `policy` when
    /// `cant` is not itself running inside a cant).
    pub effective: Policy,
    /// Whether an enclosing cant's policy was found.
    pub nested: bool,
    /// Shared libraries that could not be found (the loader will report them if needed).
    pub missing_libs: Vec<String>,
}

/// Errors from planning or launching.
#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    /// Not running on Linux.
    #[error("cants run on Linux only (this is {})", std::env::consts::OS)]
    Unsupported,
    /// The CPU architecture has no seccomp support in this build.
    #[error("unsupported CPU architecture {0}")]
    UnsupportedArch(&'static str),
    /// The executable could not be analysed.
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Elf(#[from] ElfError),
    /// Landlock is not available.
    #[error(
        "Landlock is not available on this kernel, so cants cannot be sandboxed; refusing to run (see `cant check`)"
    )]
    LandlockUnavailable,
    /// Landlock is too old to enforce the policy faithfully.
    #[error(
        "this kernel's Landlock ABI is {abi}; at least 3 (Linux 6.2) is required; refusing to run"
    )]
    LandlockTooOld {
        /// The kernel's ABI.
        abi: i32,
    },
    /// Building or applying the Landlock ruleset failed.
    #[error("Landlock setup failed: {0}")]
    Landlock(String),
    /// Building or applying a seccomp filter failed.
    #[error("seccomp setup failed: {0}")]
    Seccomp(String),
    /// A writable command-line file could not be created.
    #[error("cannot create {path}: {source}")]
    Create {
        /// The file.
        path: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
    /// The enclosing cant does not allow a file named on the command line.
    #[error("{cant} can't {verb} {shown} (not granted by the enclosing cant)")]
    ParentDenies {
        /// Cant name.
        cant: String,
        /// "read", "write" or "execute".
        verb: &'static str,
        /// The path, for display.
        shown: String,
    },
    /// The enclosing cant's policy (in `CANT_POLICY`) is malformed.
    #[error("malformed {POLICY_ENV}: {0}")]
    ParentPolicy(String),
    /// `execve` failed.
    #[error("cannot execute {program}: {source}")]
    Exec {
        /// The program.
        program: PathBuf,
        /// Cause.
        source: std::io::Error,
    },
}

/// Facts about the running kernel, for `cant check`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSupport {
    /// Landlock ABI, if Landlock is available.
    pub landlock_abi: Option<i32>,
    /// Whether this build can install seccomp filters on this architecture.
    pub seccomp_arch: bool,
}

/// Completes `built` into a launch plan.
///
/// `parent` is the policy of an enclosing cant (from [`POLICY_ENV`]), if any.
#[cfg(target_os = "linux")]
pub fn plan(
    manifest: &cant_manifest::Manifest,
    built: cant_policy::Built,
    user_args: &[OsString],
    parent: Option<&Policy>,
    home: &std::path::Path,
) -> Result<Plan, LaunchError> {
    linux::plan(manifest, built, user_args, parent, home)
}

/// Completes `built` into a launch plan (unsupported on this OS).
#[cfg(not(target_os = "linux"))]
pub fn plan(
    _manifest: &cant_manifest::Manifest,
    _built: cant_policy::Built,
    _user_args: &[OsString],
    _parent: Option<&Policy>,
    _home: &std::path::Path,
) -> Result<Plan, LaunchError> {
    Err(LaunchError::Unsupported)
}

/// Enforces `plan` and replaces the current process with the program.
/// Returns only on failure. `warn` receives non-fatal notices (printed by the CLI).
#[cfg(target_os = "linux")]
pub fn exec(plan: Plan, warn: &mut dyn FnMut(&str)) -> LaunchError {
    linux::exec(plan, warn)
}

/// Enforces `plan` and replaces the current process (unsupported on this OS).
#[cfg(not(target_os = "linux"))]
pub fn exec(_plan: Plan, _warn: &mut dyn FnMut(&str)) -> LaunchError {
    LaunchError::Unsupported
}

/// Probes kernel support. On Linux this applies a no-op Landlock ruleset to the calling
/// process (the only way to learn the ABI through the `landlock` crate), so call it only
/// from a process that is about to exit, such as `cant check`.
#[cfg(target_os = "linux")]
pub fn probe_kernel() -> KernelSupport {
    KernelSupport {
        landlock_abi: linux::landlock::probe_abi(),
        seccomp_arch: cfg!(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "riscv64"
        )),
    }
}

/// Probes kernel support (nothing is supported on this OS).
#[cfg(not(target_os = "linux"))]
pub fn probe_kernel() -> KernelSupport {
    KernelSupport {
        landlock_abi: None,
        seccomp_arch: false,
    }
}
