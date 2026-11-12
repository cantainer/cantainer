//! `cant new PROGRAM`: write a starting manifest that denies everything, with every field
//! explained in comments, for the user to open up.

use std::path::{Path, PathBuf};

/// The manifest text for a cant named `program` whose entrypoint is `entry` (a bare name or an
/// absolute path), currently found at `path`.
pub fn template(program: &str, entry: &str, path: &Path) -> String {
    format!(
        r#"# {program}: written by `cant new {program}`. It denies everything; open up what {program} needs.
# Reference: https://github.com/cantainer/cantainer/blob/main/docs/MANIFEST.md
# Check what a run would grant, without running it:  cant run --explain {program} ARGS...
manifest_version = 1
name = "{program}"
version = "0.1.0"
description = "{program}, confined"

[entrypoint]
# Now at {path}. A bare name is looked up in the system bin directories at each run.
path = "{entry}"
# Arguments always passed first, before the user's:
# args = ["--no-color"]

[args]
# What the non-option arguments (operands) are: "none" (not files), "r" (files to read) or
# "rw" (files to read and write). Only the files named on the command line are granted.
operands = "none"

[args.options]
# Options that take a value, and what the value is: "value" (not a file), "r" or "rw".
# "-o" = "rw"
# "--config" = "r"

[capabilities]
network = false        # IP sockets (TCP, UDP, ...)
unix_sockets = false   # Unix domain sockets
# Paths: absolute, "~/..." or "$CWD" (the directory `cant` runs in).
fs.ro = []             # e.g. ["/usr/share/{program}", "~/.config/{program}"]
fs.rw = []             # e.g. ["$CWD"]
exec = []              # other programs it may run, e.g. ["sh"]

[env]
# Environment variables passed through; everything else is removed. LD_* never passes.
pass = ["LANG", "LC_*", "TERM"]
"#,
        // Escaped: a path containing a newline must not add lines to the manifest.
        path = path.display().to_string().escape_debug(),
        entry = toml_escape(entry),
    )
}

fn toml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Where `cant new` writes: the first (user) directory of the search path.
pub fn destination(user_dir: &Path, program: &str) -> PathBuf {
    user_dir.join(format!("{program}.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cant_manifest::Manifest;

    #[test]
    fn template_is_a_valid_manifest() {
        let text = template("jq", "jq", Path::new("/usr/bin/jq"));
        let m = Manifest::from_toml_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        assert_eq!(m.name, "jq");
        assert!(!m.capabilities.network);
        assert!(!m.capabilities.unix_sockets);
        assert!(m.capabilities.fs.ro.is_empty());
        assert!(m.capabilities.fs.rw.is_empty());
        assert!(m.capabilities.exec.is_empty());
    }

    #[test]
    fn odd_paths_cannot_inject_lines() {
        let text = template("x", "/tmp/x", Path::new("/tmp/a\nnetwork = true\n/x"));
        let m = Manifest::from_toml_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        assert!(!m.capabilities.network);
    }

    #[test]
    fn absolute_entrypoints_are_kept() {
        let text = template(
            "tool",
            "/opt/tool/bin/tool",
            Path::new("/opt/tool/bin/tool"),
        );
        let m = Manifest::from_toml_str(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
        assert_eq!(m.entrypoint.path, "/opt/tool/bin/tool");
    }
}
