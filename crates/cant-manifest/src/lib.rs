//! Manifest ("Cantfile") types and strict validation for Cantainer.
//!
//! A manifest describes one *cant*: which executable to run, which of its arguments name files
//! (so the launcher can grant exactly those files), and what else the cant may touch.
//! The format is documented in `docs/MANIFEST.md`.
//!
//! Parsing is strict: unknown fields are rejected and every value is validated, because a
//! permissive parser in a security tool turns typos into silent grants.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The only manifest format version this crate understands.
pub const MANIFEST_VERSION: u32 = 1;

/// A parsed and validated cant manifest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Format version. Must be [`MANIFEST_VERSION`].
    pub manifest_version: u32,
    /// Short name, e.g. `cat`. Lowercase letters, digits, `.`, `_`, `-`.
    pub name: String,
    /// Version of this manifest/cant, free-form but restricted to `[A-Za-z0-9.+-]`.
    pub version: String,
    /// One-line human description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// What to execute.
    pub entrypoint: Entrypoint,
    /// How to interpret command-line arguments (powerbox grants).
    #[serde(default)]
    pub args: ArgSpec,
    /// What the cant may do beyond the files named on its command line.
    #[serde(default)]
    pub capabilities: Capabilities,
    /// Which environment variables pass through.
    #[serde(default)]
    pub env: EnvSpec,
}

/// The executable a cant runs.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entrypoint {
    /// Absolute path, `~/...` (for user-installed tools such as `~/.cargo/bin/cargo`), or a
    /// bare program name looked up in a fixed system search path (never the caller's `$PATH`).
    pub path: String,
    /// Arguments always inserted before the user's arguments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// How command-line arguments map to file grants.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArgSpec {
    /// How operands (non-option arguments) are treated.
    #[serde(default)]
    pub operands: OperandKind,
    /// Options that consume a value, keyed by spelling (`-o`, `--output`).
    /// Options not listed here are treated as flags without a value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub options: BTreeMap<String, OptionKind>,
    /// The first N operands are values (a pattern, a filter, a script), not files:
    /// `grep PATTERN FILE...`, `jq FILTER FILE...`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub value_operands: u8,
    /// If any of these options is given, there are no leading value operands, because the
    /// value came from the option (`grep -e PATTERN FILE...`). Each must be listed in `options`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub value_operands_unless: Vec<String>,
}

fn is_zero(n: &u8) -> bool {
    *n == 0
}

/// The most leading value operands a manifest may declare.
pub const MAX_VALUE_OPERANDS: u8 = 4;

/// Treatment of operands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OperandKind {
    /// Operands are not files; no grants.
    #[default]
    None,
    /// Operands are files or directories to read.
    R,
    /// Operands are files or directories to read and write.
    Rw,
}

/// Treatment of the value of an option.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OptionKind {
    /// The option takes a value that is not a file.
    Value,
    /// The value is a file or directory to read.
    R,
    /// The value is a file or directory to read and write.
    Rw,
}

/// Declared capabilities.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Capabilities {
    /// May create IP (and other non-Unix) sockets.
    #[serde(default)]
    pub network: bool,
    /// May create Unix domain sockets (and so reach local services such as D-Bus).
    #[serde(default)]
    pub unix_sockets: bool,
    /// Filesystem paths.
    #[serde(default)]
    pub fs: FsCapabilities,
    /// Programs this cant may execute (absolute paths, directories, or bare names).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec: Vec<String>,
    /// Cants this cant may run with `cant run NAME`. Its rights include theirs (minus the
    /// files later named on their command lines), so the nested cants work; `cant` itself
    /// and the manifest directories are granted too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cants: Vec<String>,
}

/// Filesystem grants. Paths may start with `~` (home) or `$CWD` (directory `cant` runs in).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FsCapabilities {
    /// Read-only paths (files or whole directory trees).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ro: Vec<String>,
    /// Read-write paths (files or whole directory trees).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rw: Vec<String>,
}

/// Environment passthrough.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSpec {
    /// Variable names to pass through. A trailing `*` matches a prefix (`LC_*`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pass: Vec<String>,
    /// Variables set to fixed values, overriding the caller's. A value of `$CWD`, `$CWD/...`,
    /// `~` or `~/...` is expanded like a manifest path.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub set: BTreeMap<String, String>,
}

/// A path as written in a manifest, before it is resolved against a home and working directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSpec {
    /// `/usr/share/vim`
    Absolute(PathBuf),
    /// `~` or `~/.vimrc` (stores the part after `~/`)
    Home(PathBuf),
    /// `$CWD` or `$CWD/src` (stores the part after `$CWD/`)
    Cwd(PathBuf),
    /// `git` — a bare program name, only allowed for executables.
    Bare(String),
}

impl PathSpec {
    /// Parses a manifest path. `allow_bare` permits bare program names.
    pub fn parse(raw: &str, allow_bare: bool) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("path is empty".into());
        }
        if raw.contains('\0') {
            return Err("path contains a NUL byte".into());
        }
        let (spec, rest) = if raw == "~" {
            (PathSpec::Home(PathBuf::new()), "")
        } else if let Some(rest) = raw.strip_prefix("~/") {
            (PathSpec::Home(PathBuf::from(rest)), rest)
        } else if raw == "$CWD" {
            (PathSpec::Cwd(PathBuf::new()), "")
        } else if let Some(rest) = raw.strip_prefix("$CWD/") {
            (PathSpec::Cwd(PathBuf::from(rest)), rest)
        } else if raw.starts_with('/') {
            (PathSpec::Absolute(PathBuf::from(raw)), raw)
        } else if raw.starts_with('~') {
            return Err(format!(
                "`{raw}`: only `~` and `~/...` are supported, not `~user`"
            ));
        } else if raw.starts_with('$') {
            return Err(format!("`{raw}`: only the `$CWD` variable is supported"));
        } else if !raw.contains('/') && allow_bare {
            if raw == "." || raw == ".." {
                return Err(format!("`{raw}` is not a program name"));
            }
            return Ok(PathSpec::Bare(raw.to_owned()));
        } else {
            return Err(format!(
                "`{raw}` is relative; use an absolute path, `~/...` or `$CWD/...`"
            ));
        };
        for component in Path::new(rest).components() {
            match component {
                Component::CurDir | Component::ParentDir => {
                    return Err(format!("`{raw}` contains `.` or `..` components"));
                }
                Component::RootDir | Component::Normal(_) | Component::Prefix(_) => {}
            }
        }
        Ok(spec)
    }

    /// Resolves to a concrete path. Bare names are returned unchanged (as a relative path);
    /// look them up with a program search first.
    pub fn resolve(&self, home: &Path, cwd: &Path) -> PathBuf {
        match self {
            PathSpec::Absolute(p) => p.clone(),
            PathSpec::Home(rest) => join_rest(home, rest),
            PathSpec::Cwd(rest) => join_rest(cwd, rest),
            PathSpec::Bare(name) => PathBuf::from(name),
        }
    }
}

fn join_rest(base: &Path, rest: &Path) -> PathBuf {
    if rest.as_os_str().is_empty() {
        base.to_path_buf()
    } else {
        base.join(rest)
    }
}

/// An environment variable name pattern: exact (`TERM`) or prefix (`LC_*`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum EnvPattern {
    /// Matches exactly this name.
    Exact(String),
    /// Matches every name starting with this prefix.
    Prefix(String),
}

impl EnvPattern {
    /// Parses and validates a pattern.
    pub fn parse(raw: &str) -> Result<Self, String> {
        let (body, is_prefix) = match raw.strip_suffix('*') {
            Some(body) => (body, true),
            None => (raw, false),
        };
        if body.is_empty() {
            return Err(format!(
                "`{raw}` would pass every variable; list the variables explicitly"
            ));
        }
        let mut chars = body.chars();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(format!(
                "`{raw}` is not a valid variable name (letters, digits, `_`, optional trailing `*`)"
            ));
        }
        // Dynamic-linker variables change what code runs inside the sandbox.
        let reaches_ld = if is_prefix {
            "LD_".starts_with(body) || body.starts_with("LD_")
        } else {
            body.starts_with("LD_")
        };
        if reaches_ld {
            return Err(format!(
                "`{raw}` would pass dynamic-linker variables (LD_*), which is not allowed"
            ));
        }
        Ok(if is_prefix {
            EnvPattern::Prefix(body.to_owned())
        } else {
            EnvPattern::Exact(body.to_owned())
        })
    }

    /// Whether `name` matches this pattern.
    pub fn matches(&self, name: &str) -> bool {
        match self {
            EnvPattern::Exact(n) => n == name,
            EnvPattern::Prefix(p) => name.starts_with(p.as_str()),
        }
    }

    /// The patterns' intersection: the names matched by both, if any.
    pub fn intersect(&self, other: &EnvPattern) -> Option<EnvPattern> {
        use EnvPattern::{Exact, Prefix};
        match (self, other) {
            (Exact(a), Exact(b)) => (a == b).then(|| self.clone()),
            (Exact(a), Prefix(_)) => other.matches(a).then(|| self.clone()),
            (Prefix(_), Exact(b)) => self.matches(b).then(|| other.clone()),
            (Prefix(a), Prefix(b)) => {
                if a.starts_with(b.as_str()) {
                    Some(self.clone())
                } else if b.starts_with(a.as_str()) {
                    Some(other.clone())
                } else {
                    None
                }
            }
        }
    }
}

impl fmt::Display for EnvPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvPattern::Exact(n) => f.write_str(n),
            EnvPattern::Prefix(p) => write!(f, "{p}*"),
        }
    }
}

impl TryFrom<String> for EnvPattern {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        EnvPattern::parse(&value)
    }
}

impl From<EnvPattern> for String {
    fn from(value: EnvPattern) -> Self {
        value.to_string()
    }
}

/// One validation problem, with the field it concerns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Dotted field path, e.g. `capabilities.fs.rw[2]`.
    pub field: String,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Errors from loading a manifest.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    /// The file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Path of the manifest.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },
    /// The TOML is malformed or has unknown/mistyped fields.
    #[error("{0}")]
    Parse(#[from] toml::de::Error),
    /// The manifest parsed but failed validation.
    #[error("invalid manifest:\n{}", .0.iter().map(|p| format!("  - {p}")).collect::<Vec<_>>().join("\n"))]
    Invalid(Vec<Problem>),
}

impl Manifest {
    /// Parses and validates a manifest from TOML text.
    pub fn from_toml_str(text: &str) -> Result<Self, ManifestError> {
        let manifest: Manifest = toml::from_str(text)?;
        let problems = manifest.problems();
        if problems.is_empty() {
            Ok(manifest)
        } else {
            Err(ManifestError::Invalid(problems))
        }
    }

    /// Reads, parses and validates a manifest file.
    pub fn from_file(path: &Path) -> Result<Self, ManifestError> {
        let text = std::fs::read_to_string(path).map_err(|source| ManifestError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&text)
    }

    /// Returns every validation problem (empty when valid).
    pub fn problems(&self) -> Vec<Problem> {
        let mut out = Vec::new();
        let mut bad = |field: String, message: String| out.push(Problem { field, message });

        if self.manifest_version != MANIFEST_VERSION {
            bad(
                "manifest_version".into(),
                format!(
                    "unsupported version {} (expected {MANIFEST_VERSION})",
                    self.manifest_version
                ),
            );
        }
        if let Err(e) = validate_name(&self.name) {
            bad("name".into(), e);
        }
        if self.version.is_empty()
            || self.version.len() > 64
            || !self
                .version
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
        {
            bad(
                "version".into(),
                "must be 1-64 characters of [A-Za-z0-9.+-]".into(),
            );
        }
        if let Some(d) = &self.description {
            if d.len() > 512 || d.contains('\n') {
                bad(
                    "description".into(),
                    "must be one line of at most 512 bytes".into(),
                );
            }
        }
        match PathSpec::parse(&self.entrypoint.path, true) {
            Ok(PathSpec::Absolute(_) | PathSpec::Bare(_)) => {}
            Ok(PathSpec::Home(p)) if !p.as_os_str().is_empty() => {}
            Ok(_) => bad(
                "entrypoint.path".into(),
                "must be an absolute path, `~/...` or a bare program name".into(),
            ),
            Err(e) => bad("entrypoint.path".into(), e),
        }
        for (i, arg) in self.entrypoint.args.iter().enumerate() {
            if arg.contains('\0') {
                bad(
                    format!("entrypoint.args[{i}]"),
                    "contains a NUL byte".into(),
                );
            }
        }
        for key in self.args.options.keys() {
            if let Err(e) = validate_option_name(key) {
                bad(format!("args.options.{key:?}"), e);
            }
        }
        if self.args.value_operands > MAX_VALUE_OPERANDS {
            bad(
                "args.value_operands".into(),
                format!("at most {MAX_VALUE_OPERANDS}"),
            );
        }
        if self.args.value_operands == 0 && !self.args.value_operands_unless.is_empty() {
            bad(
                "args.value_operands_unless".into(),
                "needs args.value_operands".into(),
            );
        }
        for (i, key) in self.args.value_operands_unless.iter().enumerate() {
            if !self.args.options.contains_key(key) {
                bad(
                    format!("args.value_operands_unless[{i}]"),
                    format!("`{key}` must also be listed in args.options"),
                );
            }
        }
        for (list, entries, bare) in [
            ("capabilities.fs.ro", &self.capabilities.fs.ro, false),
            ("capabilities.fs.rw", &self.capabilities.fs.rw, false),
            ("capabilities.exec", &self.capabilities.exec, true),
        ] {
            for (i, raw) in entries.iter().enumerate() {
                if let Err(e) = PathSpec::parse(raw, bare) {
                    bad(format!("{list}[{i}]"), e);
                }
            }
        }
        for (i, name) in self.capabilities.cants.iter().enumerate() {
            if let Err(e) = validate_name(name) {
                bad(format!("capabilities.cants[{i}]"), e);
            }
        }
        for (i, raw) in self.env.pass.iter().enumerate() {
            if let Err(e) = EnvPattern::parse(raw) {
                bad(format!("env.pass[{i}]"), e);
            }
        }
        for (name, value) in &self.env.set {
            if let Err(e) = validate_env_name(name) {
                bad(format!("env.set.{name}"), e);
            } else if value.contains('\0') {
                bad(
                    format!("env.set.{name}"),
                    "value contains a NUL byte".into(),
                );
            } else if value.starts_with("$CWD") || value.starts_with('~') {
                if let Err(e) = PathSpec::parse(value, false) {
                    bad(format!("env.set.{name}"), e);
                }
            }
        }
        out
    }

    /// The env patterns, parsed. Only valid on a validated manifest.
    pub fn env_patterns(&self) -> Vec<EnvPattern> {
        self.env
            .pass
            .iter()
            .filter_map(|p| EnvPattern::parse(p).ok())
            .collect()
    }
}

/// Names a manifest may set in `[env] set`: `[A-Za-z_][A-Za-z0-9_]*`, but not the dynamic
/// loader's `LD_*` or `cant`'s own `CANT_POLICY`.
fn validate_env_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ok {
        return Err(format!("`{name}` is not a valid variable name"));
    }
    if name.starts_with("LD_") || name == "CANT_POLICY" {
        return Err(format!("`{name}` can't be set by a manifest"));
    }
    Ok(())
}

/// Validates a cant name (also used to look manifests up by name).
pub fn validate_name(name: &str) -> Result<(), String> {
    let mut chars = name.chars();
    let first_ok = chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
    if !first_ok
        || name.len() > 64
        || !chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    {
        return Err(format!(
            "`{name}` is not a valid cant name (1-64 of [a-z0-9._-], starting with a letter or digit)"
        ));
    }
    Ok(())
}

fn validate_option_name(key: &str) -> Result<(), String> {
    let ok_chars = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    };
    if let Some(long) = key.strip_prefix("--") {
        if ok_chars(long) && !long.starts_with('-') {
            return Ok(());
        }
    } else if let Some(short) = key.strip_prefix('-') {
        if short.chars().count() == 1 && ok_chars(short) && short != "-" {
            return Ok(());
        }
    }
    Err(format!(
        "`{key}` must be a short option (`-o`) or a long option (`--output`)"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAT: &str = r#"
manifest_version = 1
name = "cat"
version = "0.1.0"
description = "Concatenate files"

[entrypoint]
path = "/usr/bin/cat"

[args]
operands = "r"

[env]
pass = ["LANG", "LC_*"]
"#;

    fn problems_of(text: &str) -> Vec<Problem> {
        match Manifest::from_toml_str(text) {
            Err(ManifestError::Invalid(p)) => p,
            other => panic!("expected validation failure, got {other:?}"),
        }
    }

    #[test]
    fn parses_minimal_manifest() {
        let m = Manifest::from_toml_str(CAT).expect("valid");
        assert_eq!(m.name, "cat");
        assert_eq!(m.args.operands, OperandKind::R);
        assert!(!m.capabilities.network);
        assert_eq!(
            m.env_patterns(),
            vec![
                EnvPattern::Exact("LANG".into()),
                EnvPattern::Prefix("LC_".into())
            ]
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let text = CAT.replace("[env]", "[capabilities]\nnetwrk = true\n[env]");
        let err = Manifest::from_toml_str(&text).expect_err("typo must fail");
        assert!(matches!(err, ManifestError::Parse(_)), "{err}");
        assert!(err.to_string().contains("netwrk"), "{err}");
    }

    #[test]
    fn rejects_unknown_top_level_field() {
        let text = format!("{CAT}\nallow_all = true\n");
        assert!(Manifest::from_toml_str(&text).is_err());
    }

    #[test]
    fn rejects_bad_operand_kind() {
        let text = CAT.replace(r#"operands = "r""#, r#"operands = "rwx""#);
        assert!(matches!(
            Manifest::from_toml_str(&text),
            Err(ManifestError::Parse(_))
        ));
    }

    #[test]
    fn rejects_wrong_version() {
        let text = CAT.replace("manifest_version = 1", "manifest_version = 2");
        let p = problems_of(&text);
        assert_eq!(p[0].field, "manifest_version");
    }

    #[test]
    fn rejects_bad_names() {
        for name in ["", "Cat", "-cat", "ca/t", "c at", &"a".repeat(65)] {
            let text = CAT.replace(r#"name = "cat""#, &format!("name = {name:?}"));
            let p = problems_of(&text);
            assert!(p.iter().any(|p| p.field == "name"), "{name}: {p:?}");
        }
    }

    #[test]
    fn home_entrypoints_and_env_set() {
        let ok = r#"
manifest_version = 1
name = "cargo"
version = "1"
[entrypoint]
path = "~/.cargo/bin/cargo"
[env]
set = { CARGO_NET_OFFLINE = "true", TMPDIR = "$CWD/target/tmp", CARGO_HOME = "~/.cargo" }
"#;
        let m = Manifest::from_toml_str(ok).expect("valid");
        assert_eq!(m.env.set["TMPDIR"], "$CWD/target/tmp");

        let bad = ok
            .replace("~/.cargo/bin/cargo", "~")
            .replace("CARGO_NET_OFFLINE", "LD_PRELOAD")
            .replace("\"$CWD/target/tmp\"", "\"$CWD/../x\"")
            .replace("CARGO_HOME", "1X");
        let fields: Vec<String> = problems_of(&bad).into_iter().map(|p| p.field).collect();
        assert_eq!(
            fields,
            vec![
                "entrypoint.path",
                "env.set.1X",
                "env.set.LD_PRELOAD",
                "env.set.TMPDIR"
            ]
        );
    }

    #[test]
    fn cants_must_be_names() {
        let text = CAT.replace(
            "[env]",
            "[capabilities]\ncants = [\"git\", \"../x\"]\n[env]",
        );
        let fields: Vec<String> = problems_of(&text).into_iter().map(|p| p.field).collect();
        assert_eq!(fields, vec!["capabilities.cants[1]"]);
    }

    #[test]
    fn value_operands_are_checked() {
        let ok = r#"
manifest_version = 1
name = "grep"
version = "1"
[entrypoint]
path = "grep"
[args]
operands = "r"
value_operands = 1
value_operands_unless = ["-e"]
[args.options]
"-e" = "value"
"#;
        let m = Manifest::from_toml_str(ok).expect("valid");
        assert_eq!(m.args.value_operands, 1);

        let bad = ok
            .replace("value_operands = 1", "value_operands = 5")
            .replace("[\"-e\"]", "[\"-e\", \"-f\"]");
        let fields: Vec<String> = problems_of(&bad).into_iter().map(|p| p.field).collect();
        assert_eq!(
            fields,
            vec!["args.value_operands", "args.value_operands_unless[1]"]
        );

        let orphan = ok.replace("value_operands = 1\n", "");
        let fields: Vec<String> = problems_of(&orphan).into_iter().map(|p| p.field).collect();
        assert_eq!(fields, vec!["args.value_operands_unless"]);
    }

    #[test]
    fn collects_all_problems() {
        let text = r#"
manifest_version = 1
name = "x"
version = "1 0"
[entrypoint]
path = "bin/x"
[capabilities]
fs.ro = ["relative/path", "~bob/x", "/a/../etc"]
fs.rw = ["$HOME/x"]
exec = ["./x"]
[env]
pass = ["*", "LD_PRELOAD", "L*", "9X"]
"#;
        let fields: Vec<String> = problems_of(text).into_iter().map(|p| p.field).collect();
        assert_eq!(
            fields,
            vec![
                "version",
                "entrypoint.path",
                "capabilities.fs.ro[0]",
                "capabilities.fs.ro[1]",
                "capabilities.fs.ro[2]",
                "capabilities.fs.rw[0]",
                "capabilities.exec[0]",
                "env.pass[0]",
                "env.pass[1]",
                "env.pass[2]",
                "env.pass[3]",
            ]
        );
    }

    #[test]
    fn entrypoint_must_be_absolute_home_or_bare() {
        for bad in ["bin/cat", "$CWD/cat", "~"] {
            let p = problems_of(&CAT.replace("/usr/bin/cat", bad));
            assert_eq!(p[0].field, "entrypoint.path", "{bad}");
        }
        Manifest::from_toml_str(&CAT.replace("/usr/bin/cat", "~/bin/cat")).expect("home ok");
        let m = Manifest::from_toml_str(&CAT.replace("/usr/bin/cat", "cat")).expect("bare ok");
        assert_eq!(m.entrypoint.path, "cat");
    }

    #[test]
    fn option_names() {
        for good in ["-o", "--output", "--dump-header", "-O"] {
            assert!(validate_option_name(good).is_ok(), "{good}");
        }
        for bad in ["o", "-", "--", "-oo", "---x", "--out=x", "--a b"] {
            assert!(validate_option_name(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn path_specs() {
        let home = Path::new("/home/u");
        let cwd = Path::new("/work");
        let r = |s: &str| PathSpec::parse(s, false).expect("valid").resolve(home, cwd);
        assert_eq!(r("~"), PathBuf::from("/home/u"));
        assert_eq!(r("~/.vimrc"), PathBuf::from("/home/u/.vimrc"));
        assert_eq!(r("$CWD"), PathBuf::from("/work"));
        assert_eq!(r("$CWD/src"), PathBuf::from("/work/src"));
        assert_eq!(r("/usr/share"), PathBuf::from("/usr/share"));
        assert!(PathSpec::parse("git", false).is_err());
        assert_eq!(
            PathSpec::parse("git", true),
            Ok(PathSpec::Bare("git".into()))
        );
        assert!(PathSpec::parse("~/a/../../etc", false).is_err());
        assert!(PathSpec::parse("..", true).is_err());
    }

    #[test]
    fn env_pattern_intersection() {
        let p = |s: &str| EnvPattern::parse(s).expect("valid");
        assert_eq!(p("LC_*").intersect(&p("LC_ALL")), Some(p("LC_ALL")));
        assert_eq!(p("LC_ALL").intersect(&p("LC_*")), Some(p("LC_ALL")));
        assert_eq!(p("LC_*").intersect(&p("LC_A*")), Some(p("LC_A*")));
        assert_eq!(p("LANG").intersect(&p("LC_*")), None);
        assert_eq!(p("TERM").intersect(&p("TERM")), Some(p("TERM")));
        assert_eq!(p("TERM").intersect(&p("HOME")), None);
    }
}
