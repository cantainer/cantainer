//! Sessions: what a watched cant changed in files that run code outside the sandbox.
//!
//! A session is recorded for each run of a watched cant (see `supervise.rs`): a snapshot of the
//! watched files before the run and one after. If anything worth reporting changed, the session
//! stays **open** and `cant` says so, at the end of the run and at every later top-level
//! `cant run` in that directory, until the user decides:
//!
//! - `cant diff ID` shows what changed,
//! - `cant revert ID` puts the files back as they were (refusing if they changed again since),
//! - `cant keep ID` accepts the change.
//!
//! Nothing is reverted automatically. Sessions live in
//! `$XDG_STATE_HOME/cantainer/sessions/` (`~/.local/state/…`), a protected path: a cant can
//! neither read the copies there (which may contain tokens from `.git/config`) nor mark its
//! own session as accepted.

use std::fmt::Write as _;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::watch::{self, FileKind, Snapshot};

/// Set by the supervising `cant` for the `cant` it starts, so that one doesn't supervise again.
pub const SUPERVISED_ENV: &str = "CANT_SUPERVISED";
/// Closed sessions (kept or reverted) are deleted after this long.
const KEEP_CLOSED_SECS: u64 = 30 * 24 * 3600;
/// Shortest session ID prefix accepted on the command line.
const MIN_PREFIX: usize = 4;
/// Length of the ID prefix `cant` shows.
pub const SHOWN_PREFIX: usize = 6;

/// Where a session is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The cant is (or was, if its supervisor died) running.
    Running,
    /// Changes were found and await a decision.
    Open,
    /// The user accepted the changes.
    Kept,
    /// The files are as they were before the session.
    Reverted,
}

impl State {
    fn word(self) -> &'static str {
        match self {
            State::Running => "running",
            State::Open => "open",
            State::Kept => "kept",
            State::Reverted => "reverted",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "running" => State::Running,
            "open" => State::Open,
            "kept" => State::Kept,
            "reverted" => State::Reverted,
            _ => return None,
        })
    }
}

/// One recorded session.
#[derive(Debug, Clone)]
pub struct Session {
    /// 32 hex digits.
    pub id: String,
    /// The session's directory.
    pub path: PathBuf,
    /// The project directory the cant ran in.
    pub cwd: PathBuf,
    /// Name of the cant.
    pub cant: String,
    /// Unix time the run started.
    pub started: u64,
    pub state: State,
}

impl Session {
    /// The ID as shown to people.
    pub fn short(&self) -> &str {
        &self.id[..SHOWN_PREFIX]
    }

    fn write_meta(&self) -> io::Result<()> {
        let text = format!(
            "cant={}\nstarted={}\nstate={}\n",
            self.cant,
            self.started,
            self.state.word()
        );
        let tmp = self.path.join("meta.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(tmp, self.path.join("meta"))
    }

    fn snapshot(&self, which: &str) -> Result<Snapshot, String> {
        watch::load(&self.path.join(which))
            .map_err(|e| format!("session {}: {which}: {e}", self.short()))
    }

    fn set_state(&mut self, state: State) -> Result<(), String> {
        self.state = state;
        self.write_meta()
            .map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

/// `$XDG_STATE_HOME/cantainer/sessions`, or `~/.local/state/cantainer/sessions`.
pub fn root(home: &Path) -> PathBuf {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(p) if Path::new(&p).is_absolute() => PathBuf::from(p),
        _ => home.join(".local/state"),
    };
    base.join("cantainer/sessions")
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn ago(t: u64) -> String {
    let s = now().saturating_sub(t);
    match s {
        0..60 => "just now".into(),
        60..3600 => format!("{} min ago", s / 60),
        3600..86400 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86400),
    }
}

fn random_id() -> io::Result<String> {
    use std::io::Read;
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Process start time (clock ticks since boot), to tell a live supervisor from a reused PID.
fn start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = &stat[stat.rfind(')')? + 1..];
    // Fields after the command name start at field 3 (state); start time is field 22.
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn read_session(path: &Path) -> io::Result<Session> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "corrupt session");
    let id = path
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or_else(bad)?
        .to_string();
    let meta = std::fs::read_to_string(path.join("meta"))?;
    let (mut cant, mut started, mut state) = (None, None, None);
    for line in meta.lines() {
        match line.split_once('=') {
            Some(("cant", v)) => cant = Some(v.to_string()),
            Some(("started", v)) => started = v.parse().ok(),
            Some(("state", v)) => state = State::from_word(v),
            _ => {}
        }
    }
    // Written by `begin`, which only records UTF-8 directory names.
    let cwd = PathBuf::from(std::fs::read_to_string(path.join("directory"))?);
    Ok(Session {
        id,
        path: path.to_path_buf(),
        cwd,
        cant: cant.ok_or_else(bad)?,
        started: started.ok_or_else(bad)?,
        state: state.ok_or_else(bad)?,
    })
}

/// All sessions, newest first. Unreadable ones are skipped.
pub fn list(home: &Path) -> Vec<Session> {
    let Ok(rd) = std::fs::read_dir(root(home)) else {
        return Vec::new();
    };
    let mut out: Vec<Session> = rd
        .filter_map(Result::ok)
        .filter_map(|e| read_session(&e.path()).ok())
        .collect();
    out.sort_by(|a, b| b.started.cmp(&a.started).then(a.id.cmp(&b.id)));
    out
}

/// Deletes closed sessions older than [`KEEP_CLOSED_SECS`].
fn gc(home: &Path) {
    for s in list(home) {
        if matches!(s.state, State::Kept | State::Reverted)
            && now().saturating_sub(s.started) > KEEP_CLOSED_SECS
        {
            let _ = std::fs::remove_dir_all(&s.path);
        }
    }
}

/// Starts a session: records the watched files in `cwd` before `cant` runs.
pub fn begin(home: &Path, cwd: &Path, cant: &str) -> io::Result<(Session, Snapshot)> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let root = root(home);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    gc(home);
    let id = random_id()?;
    let path = root.join(&id);
    std::fs::DirBuilder::new().mode(0o700).create(&path)?;
    let session = Session {
        id,
        path,
        cwd: cwd.to_path_buf(),
        cant: cant.to_string(),
        started: now(),
        state: State::Running,
    };
    let path_text = cwd.to_str().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "directory name is not UTF-8")
    })?;
    std::fs::write(session.path.join("directory"), path_text)?;
    let me = std::process::id();
    let started = start_time(me).unwrap_or(0);
    std::fs::write(session.path.join("running"), format!("{me} {started}"))?;
    session.write_meta()?;
    let before = watch::collect(cwd);
    watch::save(&session.path.join("before"), &before)?;
    Ok((session, before))
}

/// The message for an open session.
fn announce(s: &Session, changes: &[&watch::Change], truncated: bool) -> String {
    let id = s.short();
    let mut text = format!(
        "{} changed files that can run code outside the sandbox:\n{}",
        s.cant,
        watch::describe(changes, false)
    );
    if truncated {
        text.push_str("  (not everything was checked: too many files)\n");
    }
    let _ = write!(
        text,
        "review: cant diff {id}    undo: cant revert {id}    accept: cant keep {id}"
    );
    text
}

/// Ends a session with the files as they are now. Returns the message to show if something
/// worth reporting changed; otherwise the session is deleted.
pub fn finish(mut s: Session, before: &Snapshot) -> io::Result<Option<String>> {
    let after = watch::collect(&s.cwd);
    finish_with(&mut s, before, &after)
}

fn finish_with(s: &mut Session, before: &Snapshot, after: &Snapshot) -> io::Result<Option<String>> {
    watch::save(&s.path.join("after"), after)?;
    let changes = watch::diff(before, after);
    let report = watch::reportable(&changes);
    let _ = std::fs::remove_file(s.path.join("running"));
    if report.is_empty() {
        std::fs::remove_dir_all(&s.path)?;
        return Ok(None);
    }
    s.state = State::Open;
    s.write_meta()?;
    Ok(Some(announce(
        s,
        &report,
        before.truncated || after.truncated,
    )))
}

fn supervisor_alive(s: &Session) -> bool {
    let Ok(text) = std::fs::read_to_string(s.path.join("running")) else {
        return false;
    };
    let mut parts = text.split_whitespace();
    let (Some(pid), Some(start)) = (
        parts.next().and_then(|p| p.parse::<u32>().ok()),
        parts.next().and_then(|p| p.parse::<u64>().ok()),
    ) else {
        return false;
    };
    start_time(pid) == Some(start)
}

/// Paths of the reportable changes in a session.
fn changed_paths(before: &Snapshot, after: &Snapshot) -> Vec<String> {
    watch::reportable(&watch::diff(before, after))
        .into_iter()
        .map(|c| c.path.clone())
        .collect()
}

/// Open sessions for `cwd`, after closing those whose files are back as they were and
/// finishing those whose supervisor died (killed, crashed) before it could check.
pub fn pending(home: &Path, cwd: &Path) -> Vec<Session> {
    let mut current: Option<Snapshot> = None;
    let mut out = Vec::new();
    for mut s in list(home).into_iter().filter(|s| s.cwd == cwd) {
        match s.state {
            State::Running if supervisor_alive(&s) => continue,
            State::Running => {
                let Ok(before) = s.snapshot("before") else {
                    continue;
                };
                let now = current.get_or_insert_with(|| watch::collect(cwd)).clone();
                match finish_with(&mut s, &before, &now) {
                    Ok(Some(_)) => out.push(s),
                    _ => continue,
                }
            }
            State::Open => {
                let (Ok(before), Ok(after)) = (s.snapshot("before"), s.snapshot("after")) else {
                    out.push(s);
                    continue;
                };
                let now = current.get_or_insert_with(|| watch::collect(cwd));
                let back = changed_paths(&before, &after).iter().all(|p| {
                    match (before.entries.get(p), now.entries.get(p)) {
                        (None, None) => true,
                        (Some(b), Some(n)) => b.same(n),
                        _ => false,
                    }
                });
                if back {
                    let _ = s.set_state(State::Reverted);
                } else {
                    out.push(s);
                }
            }
            State::Kept | State::Reverted => {}
        }
    }
    out
}

/// One line per open session, for the start of a `cant run`.
pub fn reminder(sessions: &[Session]) -> Vec<String> {
    sessions
        .iter()
        .map(|s| {
            let id = s.short();
            format!(
                "unresolved changes by {} ({}) to files that can run code outside the sandbox: \
                 cant diff {id} | cant revert {id} | cant keep {id}",
                s.cant,
                ago(s.started)
            )
        })
        .collect()
}

/// The session whose ID starts with `prefix`.
pub fn find(home: &Path, prefix: &str) -> Result<Session, String> {
    let prefix = prefix.to_ascii_lowercase();
    if prefix.len() < MIN_PREFIX || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "`{prefix}` is not a session ID (at least {MIN_PREFIX} hex digits; see `cant log`)"
        ));
    }
    let mut found: Vec<Session> = list(home)
        .into_iter()
        .filter(|s| s.id.starts_with(&prefix))
        .collect();
    match found.len() {
        0 => Err(format!(
            "no session {prefix} (see `cant log`; inside a cant, sessions can't be read)"
        )),
        1 => Ok(found.remove(0)),
        n => Err(format!(
            "{n} sessions start with {prefix}; give more digits"
        )),
    }
}

/// `cant diff`: what a session changed.
pub fn describe(s: &Session) -> Result<String, String> {
    let mut text = format!(
        "session {} ({}): {} in {}, {}\n",
        s.short(),
        s.state.word(),
        s.cant,
        s.cwd.display(),
        ago(s.started)
    );
    if s.state == State::Running {
        text.push_str("still running\n");
        return Ok(text);
    }
    let changes = watch::diff(&s.snapshot("before")?, &s.snapshot("after")?);
    let report = watch::reportable(&changes);
    if report.is_empty() {
        text.push_str("no changes worth reporting\n");
    } else {
        text.push_str(&watch::describe(&report, true));
    }
    Ok(text)
}

/// `cant keep`: accept a session's changes.
pub fn keep(mut s: Session) -> Result<String, String> {
    match s.state {
        State::Open => {
            s.set_state(State::Kept)?;
            Ok(format!("kept the changes of session {}", s.short()))
        }
        other => Err(format!(
            "session {} is {}, not open",
            s.short(),
            other.word()
        )),
    }
}

/// `cant revert`: put every file the session changed back as it was before it. Refuses if a
/// file changed again since the session ended, unless `force`.
pub fn revert(mut s: Session, force: bool) -> Result<String, String> {
    if s.state == State::Running {
        return Err(format!("session {} is still running", s.short()));
    }
    let before = s.snapshot("before")?;
    let after = s.snapshot("after")?;
    let changes = watch::diff(&before, &after);
    if changes.is_empty() {
        return Ok(format!("session {}: nothing to revert", s.short()));
    }
    let current = watch::collect(&s.cwd);
    let conflicts: Vec<&str> = changes
        .iter()
        .filter(|c| {
            let same = match (after.entries.get(&c.path), current.entries.get(&c.path)) {
                (None, None) => true,
                (Some(a), Some(n)) => a.same(n),
                _ => false,
            };
            !same
        })
        .map(|c| c.path.as_str())
        .collect();
    if !conflicts.is_empty() && !force {
        return Err(format!(
            "can't revert session {id}: changed again since it ended: {}; \
             check with `cant diff {id}`, then `cant revert --force {id}` to overwrite",
            conflicts.join(", "),
            id = s.short()
        ));
    }
    for c in &changes {
        if let Some(b) = before.entries.get(&c.path) {
            if matches!(b.kind, FileKind::File | FileKind::Symlink) && b.content.is_none() {
                return Err(format!(
                    "can't revert {}: the original was larger than {} KiB and wasn't kept",
                    c.path,
                    watch::MAX_BLOB / 1024
                ));
            }
        }
    }
    let paths: Vec<&str> = changes.iter().map(|c| c.path.as_str()).collect();
    restore::apply(&s.cwd, &paths, &before, &current, &s.id)?;
    s.set_state(State::Reverted)?;
    Ok(format!(
        "reverted session {}: {} path(s) in {}",
        s.short(),
        paths.len(),
        s.cwd.display()
    ))
}

/// `cant log`: sessions, newest first, optionally for one directory.
pub fn log(home: &Path, dir: Option<&Path>) -> String {
    let mut out = String::new();
    for s in list(home) {
        if dir.is_some_and(|d| d != s.cwd) {
            continue;
        }
        let _ = writeln!(
            out,
            "{}  {:<8} {:<12} {:<12} {}",
            s.short(),
            s.state.word(),
            s.cant,
            ago(s.started),
            s.cwd.display()
        );
    }
    if out.is_empty() {
        out.push_str("no sessions with changes\n");
    }
    out
}

#[cfg(target_os = "linux")]
mod restore {
    //! Writing files back without following links: every directory on the way is opened with
    //! `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` relative to the project directory, and
    //! files are written to a new temporary name and renamed into place. A cant that swapped a
    //! directory for a symlink to `~/.ssh` can't make the revert write there.

    use std::io::Write as _;
    use std::os::fd::OwnedFd;
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    use rustix::fs::{
        AtFlags, Mode, OFlags, ResolveFlags, fchmod, mkdirat, open, openat, openat2, renameat,
        symlinkat, unlinkat,
    };
    use rustix::io::Errno;

    use crate::watch::{FileKind, Snapshot};

    fn split(path: &str) -> (&str, &str) {
        match path.rsplit_once('/') {
            Some((dir, name)) => (dir, name),
            None => ("", path),
        }
    }

    fn open_beneath(dir: &OwnedFd, name: &str) -> rustix::io::Result<OwnedFd> {
        openat2(
            dir,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
        )
    }

    /// The directory containing `rel`, created as needed when `create`.
    fn parent(root: &OwnedFd, rel: &str, create: bool) -> Result<Option<OwnedFd>, String> {
        let err = |e: Errno| format!("{rel}: {e}");
        let (dir, _) = split(rel);
        let mut fd = root.try_clone().map_err(|e| format!("{rel}: {e}"))?;
        if dir.is_empty() {
            return Ok(Some(fd));
        }
        for comp in dir.split('/') {
            fd = match open_beneath(&fd, comp) {
                Ok(next) => next,
                Err(Errno::NOENT) if create => {
                    mkdirat(&fd, comp, Mode::from_raw_mode(0o755)).map_err(err)?;
                    open_beneath(&fd, comp).map_err(err)?
                }
                Err(Errno::NOENT) => return Ok(None),
                Err(e) => return Err(err(e)),
            };
        }
        Ok(Some(fd))
    }

    fn depth(p: &str) -> usize {
        p.matches('/').count()
    }

    pub fn apply(
        cwd: &Path,
        paths: &[&str],
        before: &Snapshot,
        current: &Snapshot,
        tag: &str,
    ) -> Result<(), String> {
        let root = open(
            cwd,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| format!("{}: {e}", cwd.display()))?;

        // 1. Remove what wasn't there, or is of another kind, deepest first.
        let mut order: Vec<&str> = paths.to_vec();
        order.sort_by_key(|p| std::cmp::Reverse(depth(p)));
        for p in &order {
            let Some(now) = current.entries.get(*p) else {
                continue;
            };
            let remove = match before.entries.get(*p) {
                None => true,
                Some(want) => {
                    now.kind != want.kind
                        && (now.kind == FileKind::Dir || want.kind == FileKind::Dir)
                }
            };
            if !remove {
                continue;
            }
            let Some(dir) = parent(&root, p, false)? else {
                continue;
            };
            let flags = if now.kind == FileKind::Dir {
                AtFlags::REMOVEDIR
            } else {
                AtFlags::empty()
            };
            match unlinkat(&dir, split(p).1, flags) {
                Ok(()) | Err(Errno::NOENT) => {}
                Err(Errno::NOTEMPTY) => {
                    return Err(format!(
                        "{p} is a directory with other files in it; remove it yourself and retry"
                    ));
                }
                Err(e) => return Err(format!("{p}: {e}")),
            }
        }

        // 2. Put back what was there, shallowest first.
        order.reverse();
        for (n, p) in order.iter().enumerate() {
            let Some(want) = before.entries.get(*p) else {
                continue;
            };
            if current.entries.get(*p).is_some_and(|now| now.same(want)) {
                continue;
            }
            let dir = parent(&root, p, true)?.ok_or_else(|| format!("{p}: no parent"))?;
            let name = split(p).1;
            let mode = Mode::from_raw_mode(want.mode);
            let err = |e: Errno| format!("{p}: {e}");
            match want.kind {
                FileKind::Dir => {
                    match mkdirat(&dir, name, mode) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(e) => return Err(err(e)),
                    }
                    let fd = open_beneath(&dir, name).map_err(err)?;
                    fchmod(&fd, mode).map_err(err)?;
                }
                FileKind::File => {
                    let tmp = format!(".cant-revert-{}-{n}", &tag[..12]);
                    let fd = openat(
                        &dir,
                        tmp.as_str(),
                        OFlags::WRONLY
                            | OFlags::CREATE
                            | OFlags::EXCL
                            | OFlags::NOFOLLOW
                            | OFlags::CLOEXEC,
                        Mode::from_raw_mode(0o600),
                    )
                    .map_err(err)?;
                    let mut file = std::fs::File::from(fd);
                    let content = want.content.as_deref().unwrap_or_default();
                    let written = file
                        .write_all(content)
                        .and_then(|()| file.sync_all())
                        .map_err(|e| format!("{p}: {e}"))
                        .and_then(|()| fchmod(&file, mode).map_err(err))
                        .and_then(|()| renameat(&dir, tmp.as_str(), &dir, name).map_err(err));
                    if written.is_err() {
                        let _ = unlinkat(&dir, tmp.as_str(), AtFlags::empty());
                    }
                    written?;
                }
                FileKind::Symlink => {
                    let tmp = format!(".cant-revert-{}-{n}", &tag[..12]);
                    let target =
                        std::ffi::OsStr::from_bytes(want.content.as_deref().unwrap_or_default());
                    symlinkat(target, &dir, tmp.as_str()).map_err(err)?;
                    if let Err(e) = renameat(&dir, tmp.as_str(), &dir, name) {
                        let _ = unlinkat(&dir, tmp.as_str(), AtFlags::empty());
                        return Err(err(e));
                    }
                }
                FileKind::Other => {
                    return Err(format!("{p}: can't restore a special file"));
                }
            }
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod restore {
    use std::path::Path;

    use crate::watch::Snapshot;

    pub fn apply(
        _cwd: &Path,
        _paths: &[&str],
        _before: &Snapshot,
        _current: &Snapshot,
        _tag: &str,
    ) -> Result<(), String> {
        Err(format!(
            "reverting needs Linux (this is {})",
            std::env::consts::OS
        ))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    struct Fx {
        _dir: tempfile::TempDir,
        home: PathBuf,
        work: PathBuf,
    }

    fn fx() -> Fx {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(dir.path()).expect("canonical");
        let home = root.join("home");
        let work = root.join("work");
        std::fs::create_dir_all(work.join(".git/hooks")).expect("mkdir");
        std::fs::create_dir_all(&home).expect("mkdir");
        std::fs::write(work.join(".git/config"), "[core]\n\tbare = false\n").expect("write");
        Fx {
            _dir: dir,
            home,
            work,
        }
    }

    /// Sessions go under `home`, unless XDG_STATE_HOME points elsewhere; then these tests
    /// would write into the developer's real state directory, so they skip.
    fn isolated() -> bool {
        let ok = std::env::var_os("XDG_STATE_HOME").is_none();
        if !ok {
            eprintln!("SKIP: XDG_STATE_HOME is set");
        }
        ok
    }

    fn plant(f: &Fx) {
        std::fs::write(
            f.work.join(".git/config"),
            "[core]\n\tbare = false\n\tfsmonitor = /tmp/evil\n",
        )
        .expect("write");
        std::fs::write(f.work.join(".git/hooks/post-checkout"), "#!/bin/sh\nid\n").expect("write");
        std::fs::write(f.work.join(".envrc"), "evil\n").expect("write");
    }

    #[test]
    fn unchanged_run_leaves_no_session() {
        if !isolated() {
            return;
        }
        let f = fx();
        let (s, before) = begin(&f.home, &f.work, "agent-sh").expect("begin");
        assert!(finish(s, &before).expect("finish").is_none());
        assert!(list(&f.home).is_empty());
    }

    #[test]
    fn changes_open_a_session_that_reverts_exactly() {
        if !isolated() {
            return;
        }
        let f = fx();
        let (s, before) = begin(&f.home, &f.work, "agent-sh").expect("begin");
        plant(&f);
        let msg = finish(s, &before).expect("finish").expect("changes");
        assert!(msg.contains("core.fsmonitor = /tmp/evil"), "{msg}");
        let open = pending(&f.home, &f.work);
        assert_eq!(open.len(), 1);
        let id = open[0].short().to_string();
        assert!(msg.contains(&format!("cant revert {id}")), "{msg}");
        assert!(
            describe(&find(&f.home, &id).expect("find"))
                .expect("diff")
                .contains("+ \tfsmonitor")
        );

        revert(find(&f.home, &id).expect("find"), false).expect("revert");
        assert_eq!(
            std::fs::read_to_string(f.work.join(".git/config")).expect("read"),
            "[core]\n\tbare = false\n"
        );
        assert!(!f.work.join(".git/hooks/post-checkout").exists());
        assert!(!f.work.join(".envrc").exists());
        assert!(pending(&f.home, &f.work).is_empty());
    }

    #[test]
    fn revert_refuses_files_changed_again_unless_forced() {
        if !isolated() {
            return;
        }
        let f = fx();
        let (s, before) = begin(&f.home, &f.work, "agent-sh").expect("begin");
        plant(&f);
        finish(s, &before).expect("finish").expect("changes");
        std::fs::write(f.work.join(".envrc"), "the user's own edit\n").expect("write");
        let id = pending(&f.home, &f.work)[0].short().to_string();
        let err = revert(find(&f.home, &id).expect("find"), false).expect_err("conflict");
        assert!(err.contains(".envrc"), "{err}");
        assert!(
            f.work.join(".git/hooks/post-checkout").exists(),
            "nothing reverted"
        );
        revert(find(&f.home, &id).expect("find"), true).expect("forced");
        assert!(!f.work.join(".envrc").exists());
    }

    #[test]
    fn revert_does_not_follow_a_planted_symlink() {
        if !isolated() {
            return;
        }
        let f = fx();
        std::fs::write(f.work.join(".git/hooks/pre-commit"), "original\n").expect("write");
        let (s, before) = begin(&f.home, &f.work, "agent-sh").expect("begin");
        // The cant replaces the hooks directory with a link to somewhere it wants written.
        let outside = f.home.join("outside");
        std::fs::create_dir_all(&outside).expect("mkdir");
        std::fs::remove_file(f.work.join(".git/hooks/pre-commit")).expect("rm");
        std::fs::remove_dir(f.work.join(".git/hooks")).expect("rmdir");
        std::os::unix::fs::symlink(&outside, f.work.join(".git/hooks")).expect("symlink");
        finish(s, &before).expect("finish").expect("changes");
        let id = pending(&f.home, &f.work)[0].short().to_string();
        revert(find(&f.home, &id).expect("find"), false).expect("revert");
        assert!(
            !outside.join("pre-commit").exists(),
            "wrote through the link"
        );
        assert!(
            std::fs::symlink_metadata(f.work.join(".git/hooks"))
                .expect("stat")
                .is_dir()
        );
        assert_eq!(
            std::fs::read_to_string(f.work.join(".git/hooks/pre-commit")).expect("read"),
            "original\n"
        );
    }

    #[test]
    fn keep_closes_and_dead_supervisor_is_finished_later() {
        if !isolated() {
            return;
        }
        let f = fx();
        let (s, before) = begin(&f.home, &f.work, "agent-sh").expect("begin");
        plant(&f);
        // The supervisor dies before checking: pretend by pointing `running` at a dead PID.
        std::fs::write(s.path.join("running"), "999999999 1").expect("write");
        drop(before);
        let open = pending(&f.home, &f.work);
        assert_eq!(
            open.len(),
            1,
            "the stale session was finished at the next check"
        );
        keep(find(&f.home, open[0].short()).expect("find")).expect("keep");
        assert!(pending(&f.home, &f.work).is_empty());
        assert!(log(&f.home, None).contains("kept"));
    }

    #[test]
    fn short_or_unknown_ids_are_refused() {
        if !isolated() {
            return;
        }
        let f = fx();
        assert!(find(&f.home, "ab").is_err());
        assert!(find(&f.home, "zzzz").is_err());
        assert!(find(&f.home, "abcd").is_err());
    }
}
