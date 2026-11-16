//! Running a watched cant under a supervisor, so that its changes can be checked once it and
//! everything it started have finished.
//!
//! The supervisor is the `cant` the user started. It stays outside the sandbox, becomes a
//! *child subreaper* (so processes the cant detaches are re-parented to it rather than to
//! init), and starts `cant` again with the same arguments and [`SUPERVISED_ENV`] set. That
//! second `cant` plans, restricts itself and `exec`s the program exactly as an unwatched cant
//! does.
//!
//! - **Exit status** is the program's. If it died from a signal, the supervisor dies from the
//!   same signal.
//! - **Terminal:** the child stays in the supervisor's process group, so `^C`, `^\` and `^Z`
//!   from the terminal reach it directly, and the supervisor neither forwards nor dies from
//!   them. `SIGTERM`, `SIGHUP`, `SIGUSR1` and `SIGUSR2` sent to the supervisor are forwarded.
//!   When stdin isn't a terminal, `SIGINT` and `SIGQUIT` are forwarded too (an agent harness
//!   stopping the command).
//! - **Leftovers:** processes still running [`GRACE`] after the program exited are killed and
//!   reported, so nothing the cant started can change files after the check.
//!
//! [`SUPERVISED_ENV`]: crate::session::SUPERVISED_ENV

/// How long processes the program left behind may keep running after it exits.
#[cfg(target_os = "linux")]
pub const GRACE: std::time::Duration = std::time::Duration::from_secs(2);

/// How the supervised program ended.
#[derive(Debug)]
pub struct Outcome {
    /// Exit status, or the signal that terminated it.
    pub status: Status,
    /// Names of the processes it left running that had to be killed.
    pub killed: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    not(target_os = "linux"),
    expect(dead_code, reason = "only Linux runs cants")
)]
pub enum Status {
    Exited(i32),
    Signaled(i32),
}

#[cfg(target_os = "linux")]
pub use linux::run;

#[cfg(not(target_os = "linux"))]
pub fn run(_session: &str) -> std::io::Result<Outcome> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "supervision needs Linux",
    ))
}

/// Ends this process the way the program ended.
pub fn exit_like(status: Status) -> std::process::ExitCode {
    match status {
        Status::Exited(code) => std::process::ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Status::Signaled(sig) => {
            // Die from the same signal, so a shell sees what it would have seen.
            let _ = signal_hook::low_level::emulate_default_handler(sig);
            std::process::ExitCode::from(u8::try_from(128 + sig).unwrap_or(1))
        }
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{self, IsTerminal as _};
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::time::Instant;

    use rustix::io::Errno;
    use rustix::process::{
        Pid, Signal, WaitOptions, getpid, kill_process, set_child_subreaper, wait,
    };
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2};
    use signal_hook::iterator::Signals;

    use super::{GRACE, Outcome, Status};
    use crate::session::SUPERVISED_ENV;

    fn to_signal(raw: i32) -> Option<Signal> {
        Some(match raw {
            SIGHUP => Signal::HUP,
            SIGINT => Signal::INT,
            SIGQUIT => Signal::QUIT,
            SIGTERM => Signal::TERM,
            SIGUSR1 => Signal::USR1,
            SIGUSR2 => Signal::USR2,
            _ => return None,
        })
    }

    /// Direct children of this process (re-parented orphans included), from /proc.
    fn children() -> Vec<(i32, String)> {
        let me = getpid().as_raw_nonzero().get();
        let Ok(rd) = std::fs::read_dir("/proc") else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for e in rd.filter_map(Result::ok) {
            let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<i32>().ok()) else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(e.path().join("stat")) else {
                continue;
            };
            let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
                continue;
            };
            let ppid = stat[close + 1..]
                .split_whitespace()
                .nth(1)
                .and_then(|p| p.parse::<i32>().ok());
            if ppid == Some(me) {
                out.push((pid, stat[open + 1..close].to_string()));
            }
        }
        out
    }

    /// Reaps every child that has exited. Returns false once there are no children left.
    fn reap_ready() -> bool {
        loop {
            match wait(WaitOptions::NOHANG) {
                Ok(Some(_)) => continue,
                Ok(None) => return true,
                Err(Errno::INTR) => continue,
                Err(_) => return false, // ECHILD: none left
            }
        }
    }

    pub fn run(session: &str) -> io::Result<Outcome> {
        set_child_subreaper(Some(getpid()))?;

        // Handlers (not SIG_IGN) so that the child, after exec, gets default dispositions.
        let child_pid = Arc::new(AtomicI32::new(0));
        let mut signals = Signals::new([SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2])?;
        let forward_tty_signals = !io::stdin().is_terminal();
        {
            let child_pid = Arc::clone(&child_pid);
            std::thread::spawn(move || {
                for raw in signals.forever() {
                    let from_terminal = matches!(raw, SIGINT | SIGQUIT);
                    if from_terminal && !forward_tty_signals {
                        continue; // the terminal sent it to the child's process group already
                    }
                    let (Some(pid), Some(sig)) = (
                        Pid::from_raw(child_pid.load(Ordering::SeqCst)),
                        to_signal(raw),
                    ) else {
                        continue;
                    };
                    let _ = kill_process(pid, sig);
                }
            });
        }

        let exe = std::env::current_exe()?;
        let child = Command::new(exe)
            .args(std::env::args_os().skip(1))
            .env(SUPERVISED_ENV, session)
            .spawn()?;
        let main =
            i32::try_from(child.id()).map_err(|_| io::Error::other("child PID out of range"))?;
        child_pid.store(main, Ordering::SeqCst);

        // Wait for the program, reaping re-parented orphans along the way.
        let status = loop {
            match wait(WaitOptions::empty()) {
                Ok(Some((pid, st))) if pid.as_raw_nonzero().get() == main => {
                    if let Some(sig) = st.terminating_signal() {
                        break Status::Signaled(sig);
                    }
                    break Status::Exited(st.exit_status().unwrap_or(1));
                }
                Ok(_) | Err(Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
        };
        child_pid.store(0, Ordering::SeqCst);

        // Give what it left behind a moment to finish, then stop it.
        let deadline = Instant::now() + GRACE;
        let mut killed = Vec::new();
        while reap_ready() {
            if Instant::now() >= deadline {
                let left = children();
                if left.is_empty() {
                    // Exited but not yet reapable; wait for it.
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    continue;
                }
                for (pid, name) in left {
                    if let Some(pid) = Pid::from_raw(pid) {
                        if kill_process(pid, Signal::KILL).is_ok() && !killed.contains(&name) {
                            killed.push(name);
                        }
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Ok(Outcome { status, killed })
    }
}
