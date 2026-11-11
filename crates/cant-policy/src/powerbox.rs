//! Powerbox: find the file arguments on a command line.
//!
//! The command line is the permission. `vim notes.txt` names `notes.txt`, so vim gets
//! `notes.txt`. Which arguments are files is declared by the manifest's `[args]` table.
//!
//! Parsing follows getopt conventions: `--` ends options, `-` is stdin, `--long=value`
//! and `--long value`, `-o value` and `-ovalue`, and clustered short flags (`-nE`).
//! Options the manifest does not list are treated as flags without a value. If such an
//! option really takes a value, that value is treated as an operand, which can only
//! *add* a grant for something the user typed; it never removes one.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use cant_manifest::{ArgSpec, OperandKind, OptionKind};

use crate::Access;

/// An argument that names a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileArg {
    /// Index into the user's argument list.
    pub index: usize,
    /// The file name as typed (for `--out=x`, just `x`).
    pub value: OsString,
    /// Requested access.
    pub access: Access,
}

fn operand_access(kind: OperandKind) -> Option<Access> {
    match kind {
        OperandKind::None => None,
        OperandKind::R => Some(Access::R),
        OperandKind::Rw => Some(Access::RW),
    }
}

fn option_access(kind: OptionKind) -> Option<Access> {
    match kind {
        OptionKind::Value => None,
        OptionKind::R => Some(Access::R),
        OptionKind::Rw => Some(Access::RW),
    }
}

/// Returns every argument that names a file, according to `spec`.
pub fn file_args(spec: &ArgSpec, args: &[OsString]) -> Vec<FileArg> {
    let mut out = Vec::new();
    let mut push = |index: usize, value: &OsStr, access: Option<Access>| {
        // An empty string or "-" (stdin/stdout) is never a file grant.
        if let Some(access) = access {
            if !value.is_empty() && value != "-" {
                out.push(FileArg {
                    index,
                    value: value.to_owned(),
                    access,
                });
            }
        }
    };

    let mut i = 0;
    let mut only_operands = false;
    while i < args.len() {
        let arg = args[i].as_os_str();
        let bytes = arg.as_bytes();
        if only_operands || bytes == b"-" || !bytes.starts_with(b"-") {
            push(i, arg, operand_access(spec.operands));
        } else if bytes == b"--" {
            only_operands = true;
        } else if let Some(long) = bytes.strip_prefix(b"--") {
            let (name, inline) = match long.iter().position(|&b| b == b'=') {
                Some(eq) => (&long[..eq], Some(&long[eq + 1..])),
                None => (long, None),
            };
            let key = format!("--{}", String::from_utf8_lossy(name));
            if let Some(&kind) = spec.options.get(&key) {
                match inline {
                    Some(v) => push(i, OsStr::from_bytes(v), option_access(kind)),
                    None if i + 1 < args.len() => {
                        i += 1;
                        push(i, &args[i], option_access(kind));
                    }
                    None => {}
                }
            }
        } else {
            // Clustered short options: scan until one takes a value.
            for (pos, &c) in bytes.iter().enumerate().skip(1) {
                let key = format!("-{}", c as char);
                if let Some(&kind) = spec.options.get(&key) {
                    let rest = &bytes[pos + 1..];
                    if !rest.is_empty() {
                        push(i, OsStr::from_bytes(rest), option_access(kind));
                    } else if i + 1 < args.len() {
                        i += 1;
                        push(i, &args[i], option_access(kind));
                    }
                    break;
                }
            }
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn spec(operands: OperandKind, opts: &[(&str, OptionKind)]) -> ArgSpec {
        ArgSpec {
            operands,
            options: opts
                .iter()
                .map(|(k, v)| (k.to_string(), *v))
                .collect::<BTreeMap<_, _>>(),
        }
    }

    fn files(spec: &ArgSpec, args: &[&str]) -> Vec<(usize, String, String)> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        file_args(spec, &args)
            .into_iter()
            .map(|f| {
                (
                    f.index,
                    f.value.to_string_lossy().into_owned(),
                    f.access.to_string(),
                )
            })
            .collect()
    }

    #[test]
    fn cat_operands_are_read() {
        let s = spec(OperandKind::R, &[]);
        assert_eq!(
            files(&s, &["-n", "a.txt", "-", "b.txt"]),
            vec![
                (1, "a.txt".into(), "r".into()),
                (3, "b.txt".into(), "r".into())
            ]
        );
    }

    #[test]
    fn double_dash_ends_options() {
        let s = spec(OperandKind::Rw, &[]);
        assert_eq!(
            files(&s, &["--", "-weird-name", "--"]),
            vec![
                (1, "-weird-name".into(), "rw".into()),
                (2, "--".into(), "rw".into())
            ]
        );
    }

    #[test]
    fn option_values() {
        let s = spec(
            OperandKind::None,
            &[
                ("-o", OptionKind::Rw),
                ("--output", OptionKind::Rw),
                ("-H", OptionKind::Value),
                ("-T", OptionKind::R),
            ],
        );
        assert_eq!(
            files(
                &s,
                &[
                    "-H",
                    "X-A: b",
                    "-o",
                    "out1",
                    "--output=out2",
                    "--output",
                    "out3",
                    "-oout4",
                    "-sSo",
                    "out5",
                    "-Tup",
                    "https://x"
                ]
            ),
            vec![
                (3, "out1".into(), "rw".into()),
                (4, "out2".into(), "rw".into()),
                (6, "out3".into(), "rw".into()),
                (7, "out4".into(), "rw".into()),
                (9, "out5".into(), "rw".into()),
                (10, "up".into(), "r".into()),
            ]
        );
    }

    #[test]
    fn value_options_hide_their_value() {
        let s = spec(OperandKind::Rw, &[("-c", OptionKind::Value)]);
        assert_eq!(
            files(&s, &["-c", "set nu", "notes.txt"]),
            vec![(2, "notes.txt".into(), "rw".into())]
        );
    }

    #[test]
    fn missing_value_at_end_is_ignored() {
        let s = spec(OperandKind::R, &[("-o", OptionKind::Rw)]);
        assert!(files(&s, &["-o"]).is_empty());
        assert!(files(&s, &["--unknown"]).is_empty());
    }

    #[test]
    fn none_operands_grant_nothing() {
        let s = spec(OperandKind::None, &[]);
        assert!(files(&s, &["status", "README.md"]).is_empty());
    }

    #[test]
    fn non_utf8_arguments() {
        use std::os::unix::ffi::OsStringExt;
        let s = spec(OperandKind::R, &[]);
        let raw = OsString::from_vec(vec![b'f', 0xff, b'x']);
        let got = file_args(&s, std::slice::from_ref(&raw));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].value, raw);
    }
}
