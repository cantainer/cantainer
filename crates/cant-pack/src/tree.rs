//! The tree: every path in a can's root, and how to start its program
//! (`spec/can-format.md` §4).

use std::collections::BTreeMap;

use cant_store::Digest;
use serde::{Deserialize, Serialize};

/// Media type of the tree blob.
pub const MEDIA_TYPE: &str = "application/vnd.cantainer.can.tree.v1+json";

/// Limits a reader enforces before writing anything (spec §5).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_entries: usize,
    pub max_total_size: u64,
    pub max_path_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entries: 100_000,
            max_total_size: 4 << 30,
            max_path_len: 4096,
        }
    }
}

/// The tree document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tree {
    pub version: u32,
    pub entries: Vec<Entry>,
    pub entrypoint: Entrypoint,
}

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    File,
    Dir,
    Symlink,
}

/// One path in the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<BundleRef>,
}

/// Where a bundled file's bytes are (spec §4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleRef {
    pub digest: String,
    pub offset: u64,
    pub length: u64,
}

/// How the program starts (spec §4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entrypoint {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub library_path: Vec<String>,
}

impl Entry {
    /// A file entry's digest, parsed. Only valid on a validated tree.
    pub fn file_digest(&self) -> Option<Digest> {
        self.digest.as_deref().and_then(|d| d.parse().ok())
    }
}

/// Checks one path against spec §4.1.
fn check_path(path: &str, limits: &Limits) -> Result<(), String> {
    if path.is_empty() {
        return Err("empty path".into());
    }
    if path.len() > limits.max_path_len {
        return Err(format!("path longer than {} bytes", limits.max_path_len));
    }
    if path.contains('\0') {
        return Err(format!("`{path}`: contains NUL"));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(format!(
            "`{path}`: must be relative, without a trailing `/`"
        ));
    }
    for comp in path.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(format!("`{path}`: empty, `.` or `..` component"));
        }
    }
    Ok(())
}

/// Resolves a symlink target against the link's directory; `None` if it would leave the
/// root at any point, or is absolute.
fn resolve_link(link: &str, target: &str) -> Option<Vec<String>> {
    if target.is_empty() || target.starts_with('/') || target.contains('\0') {
        return None;
    }
    let mut at: Vec<String> = link.split('/').map(str::to_string).collect();
    at.pop(); // the link itself
    for comp in target.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                at.pop()?;
            }
            c => at.push(c.to_string()),
        }
    }
    Some(at)
}

fn digest_ok(d: Option<&String>) -> bool {
    d.is_some_and(|d| d.parse::<Digest>().is_ok())
}

impl Tree {
    /// Every violation of the spec, or `Ok`. A reader refuses the whole can on any.
    pub fn validate(&self, limits: &Limits) -> Result<(), Vec<String>> {
        let mut bad = Vec::new();
        if self.version != 1 {
            bad.push(format!("tree version {} is not supported", self.version));
        }
        if self.entries.len() > limits.max_entries {
            bad.push(format!("more than {} entries", limits.max_entries));
            return Err(bad);
        }
        let mut kinds: BTreeMap<&str, Kind> = BTreeMap::new();
        let mut total: u64 = 0;
        for e in &self.entries {
            if let Err(msg) = check_path(&e.path, limits) {
                bad.push(msg);
                continue;
            }
            if kinds.insert(e.path.as_str(), e.kind).is_some() {
                bad.push(format!("`{}`: listed twice", e.path));
            }
            match e.kind {
                Kind::File => {
                    if !matches!(e.mode.as_deref(), Some("0755" | "0644")) {
                        bad.push(format!("`{}`: file mode must be 0755 or 0644", e.path));
                    }
                    if !digest_ok(e.digest.as_ref()) {
                        bad.push(format!("`{}`: missing or invalid digest", e.path));
                    }
                    match e.size {
                        Some(size) => total = total.saturating_add(size),
                        None => bad.push(format!("`{}`: missing size", e.path)),
                    }
                    if e.target.is_some() {
                        bad.push(format!("`{}`: a file has no target", e.path));
                    }
                    if let Some(b) = &e.bundle {
                        if !digest_ok(Some(&b.digest)) || Some(b.length) != e.size {
                            bad.push(format!("`{}`: invalid bundle reference", e.path));
                        }
                    }
                }
                Kind::Dir => {
                    if e.mode.as_deref() != Some("0755") {
                        bad.push(format!("`{}`: directory mode must be 0755", e.path));
                    }
                    if e.digest.is_some()
                        || e.size.is_some()
                        || e.target.is_some()
                        || e.bundle.is_some()
                    {
                        bad.push(format!("`{}`: a directory has only a mode", e.path));
                    }
                }
                Kind::Symlink => {
                    if e.mode.is_some()
                        || e.digest.is_some()
                        || e.size.is_some()
                        || e.bundle.is_some()
                    {
                        bad.push(format!("`{}`: a symlink has only a target", e.path));
                    }
                    let inside = e.target.as_deref().and_then(|t| resolve_link(&e.path, t));
                    if inside.is_none() {
                        bad.push(format!(
                            "`{}`: symlink target must be relative and stay inside the can",
                            e.path
                        ));
                    }
                }
            }
        }
        if total > limits.max_total_size {
            bad.push(format!(
                "more than {} bytes in total",
                limits.max_total_size
            ));
        }
        // Every parent is a directory entry, so nothing is ever created through a symlink.
        for e in &self.entries {
            let mut parent = e.path.as_str();
            while let Some((p, _)) = parent.rsplit_once('/') {
                if kinds.get(p) != Some(&Kind::Dir) {
                    bad.push(format!(
                        "`{}`: parent `{p}` is not a directory entry",
                        e.path
                    ));
                    break;
                }
                parent = p;
            }
        }
        let ep = &self.entrypoint;
        if kinds.get(ep.path.as_str()) != Some(&Kind::File) {
            bad.push(format!(
                "entrypoint `{}` is not a file in the tree",
                ep.path
            ));
        }
        if let Some(loader) = &ep.loader {
            if kinds.get(loader.as_str()) != Some(&Kind::File) {
                bad.push(format!("loader `{loader}` is not a file in the tree"));
            }
        }
        for dir in &ep.library_path {
            if kinds.get(dir.as_str()) != Some(&Kind::Dir) {
                bad.push(format!(
                    "library directory `{dir}` is not a directory in the tree"
                ));
            }
        }
        if ep.loader.is_none() && !ep.library_path.is_empty() {
            bad.push("library_path without a loader".into());
        }
        if bad.is_empty() { Ok(()) } else { Err(bad) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn file(path: &str) -> Entry {
        Entry {
            path: path.into(),
            kind: Kind::File,
            mode: Some("0755".into()),
            size: Some(3),
            digest: Some(D.into()),
            target: None,
            bundle: None,
        }
    }

    fn dir(path: &str) -> Entry {
        Entry {
            path: path.into(),
            kind: Kind::Dir,
            mode: Some("0755".into()),
            size: None,
            digest: None,
            target: None,
            bundle: None,
        }
    }

    fn link(path: &str, target: &str) -> Entry {
        Entry {
            path: path.into(),
            kind: Kind::Symlink,
            mode: None,
            size: None,
            digest: None,
            target: Some(target.into()),
            bundle: None,
        }
    }

    fn tree(mut extra: Vec<Entry>) -> Tree {
        let mut entries = vec![
            dir("usr"),
            dir("usr/bin"),
            file("usr/bin/x"),
            dir("lib"),
            file("lib/ld.so"),
        ];
        entries.append(&mut extra);
        Tree {
            version: 1,
            entries,
            entrypoint: Entrypoint {
                path: "usr/bin/x".into(),
                loader: Some("lib/ld.so".into()),
                library_path: vec!["lib".into()],
            },
        }
    }

    #[test]
    fn a_plain_tree_is_valid() {
        let t = tree(vec![
            link("usr/bin/y", "x"),
            link("usr/bin/z", "../../lib/ld.so"),
        ]);
        assert_eq!(t.validate(&Limits::default()), Ok(()));
        let json = serde_json::to_string(&t).expect("json");
        assert_eq!(serde_json::from_str::<Tree>(&json).expect("parse"), t);
    }

    #[test]
    fn hostile_entries_are_refused() {
        let mut setuid = file("usr/bin/s");
        setuid.mode = Some("4755".into());
        let mut no_digest = file("usr/bin/n");
        no_digest.digest = Some("md5:00".into());
        let cases: Vec<(Entry, &str)> = vec![
            (file("../etc/passwd"), "component"),
            (file("/etc/passwd"), "relative"),
            (file("usr/./bin/a"), "component"),
            (file("usr//a"), "component"),
            (file("usr/bin/x"), "twice"),
            (file("nodir/a"), "parent"),
            (setuid, "mode"),
            (no_digest, "digest"),
            (link("usr/bin/l", "/etc/passwd"), "inside"),
            (link("usr/bin/l", "../../../etc/passwd"), "inside"),
            (link("usr/bin/l", "../../../usr/bin/x"), "inside"),
            (link("usr/l2", ""), "inside"),
        ];
        for (entry, word) in cases {
            let shown = entry.path.clone();
            let errs = tree(vec![entry])
                .validate(&Limits::default())
                .expect_err(&shown);
            assert!(errs.iter().any(|e| e.contains(word)), "{shown}: {errs:?}");
        }
    }

    #[test]
    fn files_cannot_be_created_through_a_symlinked_directory() {
        // `usr/sub` is a link, so `usr/sub/a` would be written outside the can.
        let t = tree(vec![link("usr/sub", "../.."), file("usr/sub/a")]);
        let errs = t.validate(&Limits::default()).expect_err("refused");
        assert!(errs.iter().any(|e| e.contains("parent")), "{errs:?}");
    }

    #[test]
    fn limits_and_entrypoint_are_checked() {
        let small = Limits {
            max_entries: 3,
            ..Limits::default()
        };
        assert!(tree(vec![]).validate(&small).is_err());
        let mut t = tree(vec![]);
        t.entrypoint.path = "usr/bin".into();
        assert!(t.validate(&Limits::default()).is_err());
        let mut t = tree(vec![]);
        t.entrypoint.loader = None;
        assert!(
            t.validate(&Limits::default()).is_err(),
            "library_path without loader"
        );
        let bad_json = r#"{"version":1,"entries":[],"entrypoint":{"path":"x"},"extra":1}"#;
        assert!(serde_json::from_str::<Tree>(bad_json).is_err());
    }
}
