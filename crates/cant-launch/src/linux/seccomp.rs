//! Baseline seccomp filters.
//!
//! This is a deny list on top of Landlock, not an allow list: it removes kernel attack
//! surface and closes gaps Landlock does not cover. Three filters are installed (the kernel
//! evaluates all of them and the most restrictive result wins):
//!
//! 1. `EPERM` for dangerous syscalls, path-based metadata changes, namespace creation via
//!    `clone`, terminal injection ioctls, and `socket()` families the policy does not allow.
//! 2. `ENOSYS` for `clone3`: its flags live in memory seccomp cannot read, so we make libc
//!    fall back to `clone`, whose flags filter 1 can check.
//! 3. x86_64 only: `EPERM` for x32 syscall numbers (`nr >= 0x4000_0000`). x32 syscalls share
//!    the x86_64 audit arch, so a number-based deny list would not see them otherwise.
//!    seccompiler only checks the arch, so this small filter is written by hand.

use std::collections::BTreeMap;

use cant_policy::Policy;
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen as Len, SeccompCmpOp as Op, SeccompCondition,
    SeccompFilter, SeccompRule, TargetArch, apply_filter,
};

use crate::LaunchError;

// Syscalls added after the libc crate's tables; the numbers are shared by all architectures
// that use the unified syscall table (Linux >= 5.1, numbers >= 424).
const SYS_FCHMODAT2: i64 = 452;
const SYS_SETXATTRAT: i64 = 463;
const SYS_REMOVEXATTRAT: i64 = 466;

// kexec_file_load: the libc crate defines it for x86_64 and aarch64 glibc only.
#[cfg(target_arch = "x86_64")]
const SYS_KEXEC_FILE_LOAD: i64 = 320;
// aarch64 and riscv64 use the asm-generic table.
#[cfg(not(target_arch = "x86_64"))]
const SYS_KEXEC_FILE_LOAD: i64 = 294;

fn err(e: impl std::fmt::Display) -> LaunchError {
    LaunchError::Seccomp(e.to_string())
}

fn target_arch() -> Result<TargetArch, LaunchError> {
    if cfg!(target_arch = "x86_64") {
        Ok(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(TargetArch::aarch64)
    } else if cfg!(target_arch = "riscv64") {
        Ok(TargetArch::riscv64)
    } else {
        Err(LaunchError::UnsupportedArch(std::env::consts::ARCH))
    }
}

/// Syscalls refused outright.
fn denied_syscalls() -> Vec<i64> {
    #[allow(unused_mut)]
    let mut v = vec![
        // Debugging and memory access to other processes.
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        // Kernel, modules, system state.
        libc::SYS_kexec_load,
        SYS_KEXEC_FILE_LOAD,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_quotactl,
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_clock_adjtime,
        libc::SYS_adjtimex,
        libc::SYS_syslog,
        libc::SYS_vhangup,
        // Large attack surface rarely needed by command-line tools.
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        // io_uring can open sockets and files without the syscalls filtered here.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // Namespaces and mounts.
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        libc::SYS_move_mount,
        libc::SYS_open_tree,
        libc::SYS_mount_setattr,
        // File handles bypass path-based checks.
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        // Path-based metadata changes, which Landlock does not control.
        // (fd-based fchmod/fchown/fsetxattr/futimens stay allowed: they need an open file.)
        libc::SYS_fchmodat,
        SYS_FCHMODAT2,
        libc::SYS_fchownat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        SYS_SETXATTRAT,
        SYS_REMOVEXATTRAT,
    ];
    #[cfg(target_arch = "x86_64")]
    v.extend([
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
        libc::SYS_iopl,
        libc::SYS_ioperm,
        libc::SYS_uselib,
    ]);
    v
}

fn cond(arg: u8, len: Len, op: Op, value: u64) -> Result<SeccompCondition, LaunchError> {
    SeccompCondition::new(arg, len, op, value).map_err(err)
}

fn rule(conditions: Vec<SeccompCondition>) -> Result<SeccompRule, LaunchError> {
    SeccompRule::new(conditions).map_err(err)
}

/// Filter 1: the `EPERM` deny list, specialized for `policy`.
fn eperm_filter(policy: &Policy, arch: TargetArch) -> Result<BpfProgram, LaunchError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for nr in denied_syscalls() {
        rules.insert(nr, Vec::new()); // empty rule list = always matches
    }

    // clone(2) creating namespaces. The flags are argument 0 on x86_64, aarch64 and riscv64.
    let mut clone_rules = Vec::new();
    for flag in [
        libc::CLONE_NEWNS,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWCGROUP,
    ] {
        let flag = flag as u64;
        clone_rules.push(rule(vec![cond(0, Len::Qword, Op::MaskedEq(flag), flag)?])?);
    }
    rules.insert(libc::SYS_clone, clone_rules);

    // Terminal injection: TIOCSTI pushes input into the terminal; TIOCLINUX can too on VTs.
    // The request number is 32 bits in the kernel.
    // `Ioctl` is `c_ulong` on glibc but `c_int` on musl, hence the casts.
    #[allow(clippy::unnecessary_cast)]
    let (tiocsti, tioclinux) = (libc::TIOCSTI as u64, libc::TIOCLINUX as u64);
    rules.insert(
        libc::SYS_ioctl,
        vec![
            rule(vec![cond(1, Len::Dword, Op::Eq, tiocsti)?])?,
            rule(vec![cond(1, Len::Dword, Op::Eq, tioclinux)?])?,
        ],
    );

    // utimensat with a path (a NULL path means "this fd", like futimens).
    rules.insert(
        libc::SYS_utimensat,
        vec![rule(vec![cond(1, Len::Qword, Op::Ne, 0)?])?],
    );

    // socket(2) by address family (argument 0).
    let af_unix = libc::AF_UNIX as u64;
    match (policy.network, policy.unix_sockets) {
        (false, false) => {
            rules.insert(libc::SYS_socket, Vec::new());
        }
        (false, true) => {
            rules.insert(
                libc::SYS_socket,
                vec![rule(vec![cond(0, Len::Dword, Op::Ne, af_unix)?])?],
            );
        }
        (true, false) => {
            rules.insert(
                libc::SYS_socket,
                vec![rule(vec![cond(0, Len::Dword, Op::Eq, af_unix)?])?],
            );
        }
        (true, true) => {}
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(err)?;
    BpfProgram::try_from(filter).map_err(err)
}

/// Filter 2: `clone3` returns `ENOSYS` so libc falls back to `clone`.
fn clone3_filter(arch: TargetArch) -> Result<BpfProgram, LaunchError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    rules.insert(libc::SYS_clone3, Vec::new());
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )
    .map_err(err)?;
    BpfProgram::try_from(filter).map_err(err)
}

/// Filter 3 (x86_64): refuse x32 syscall numbers. Hand-written classic BPF:
///
/// ```text
/// 0: ld  [4]               ; seccomp_data.arch
/// 1: jeq #AUDIT_ARCH_X86_64, 2, 5
/// 2: ld  [0]               ; seccomp_data.nr
/// 3: jge #0x40000000, 4, 5
/// 4: ret #SECCOMP_RET_ERRNO|EPERM
/// 5: ret #SECCOMP_RET_ALLOW
/// ```
#[cfg(target_arch = "x86_64")]
fn x32_guard() -> BpfProgram {
    const LD_W_ABS: u16 = 0x20; // BPF_LD | BPF_W | BPF_ABS
    const JEQ_K: u16 = 0x15; // BPF_JMP | BPF_JEQ | BPF_K
    const JGE_K: u16 = 0x35; // BPF_JMP | BPF_JGE | BPF_K
    const RET_K: u16 = 0x06; // BPF_RET | BPF_K
    const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    const RET_ERRNO: u32 = 0x0005_0000;
    const RET_ALLOW: u32 = 0x7fff_0000;
    let ins = |code, jt, jf, k| seccompiler::sock_filter { code, jt, jf, k };
    vec![
        ins(LD_W_ABS, 0, 0, 4),
        ins(JEQ_K, 0, 3, AUDIT_ARCH_X86_64),
        ins(LD_W_ABS, 0, 0, 0),
        ins(JGE_K, 0, 1, X32_SYSCALL_BIT),
        ins(RET_K, 0, 0, RET_ERRNO | libc::EPERM as u32),
        ins(RET_K, 0, 0, RET_ALLOW),
    ]
}

/// Installs all filters on the calling thread. Irreversible; inherited across `exec`.
/// Requires `no_new_privs`, which the Landlock step has already set.
pub fn install(policy: &Policy) -> Result<(), LaunchError> {
    let arch = target_arch()?;
    #[cfg(target_arch = "x86_64")]
    apply_filter(&x32_guard()).map_err(err)?;
    apply_filter(&clone3_filter(arch)?).map_err(err)?;
    apply_filter(&eperm_filter(policy, arch)?).map_err(err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_compile_for_every_policy_shape() {
        let arch = target_arch().expect("supported arch");
        for (network, unix_sockets) in [(false, false), (false, true), (true, false), (true, true)]
        {
            let p = Policy {
                network,
                unix_sockets,
                ..Policy::default()
            };
            let prog = eperm_filter(&p, arch).expect("compiles");
            assert!(!prog.is_empty());
            assert!(prog.len() < 4096, "BPF_MAXINSNS");
        }
        assert!(!clone3_filter(arch).expect("compiles").is_empty());
    }

    #[test]
    fn no_duplicate_denied_syscalls() {
        let mut v = denied_syscalls();
        let n = v.len();
        v.sort_unstable();
        v.dedup();
        assert_eq!(v.len(), n);
    }
}

#[cfg(test)]
mod syscall_number_tests {
    /// Our own constants must agree with the libc crate wherever it has them.
    #[test]
    #[cfg(all(target_arch = "x86_64", target_env = "gnu"))]
    fn kexec_file_load_matches_libc() {
        assert_eq!(super::SYS_KEXEC_FILE_LOAD, libc::SYS_kexec_file_load);
    }
}
