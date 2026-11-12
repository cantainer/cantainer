# Manifest format

A manifest describes one cant: which executable runs, which of its command-line arguments are
files, and what else it may touch. Manifests are TOML. Parsing is strict: unknown fields, wrong
types and invalid values are errors, and `cant` reports all of them at once.

`cant run NAME` looks for `NAME.toml` in `~/.config/cantainer/cants/` (or
`$XDG_CONFIG_HOME/cantainer/cants/`), then in `/etc/cantainer/cants/`, then among the manifests
built into `cant` (`cant list` shows them all and where each comes from). The current directory
is never searched. `cant run path/to/x.toml` uses that file directly. The file name should match
`name`.

To change a built-in manifest, copy it and edit the copy; it takes precedence:

```sh
mkdir -p ~/.config/cantainer/cants
cant show git > ~/.config/cantainer/cants/git.toml
```

Cants can read `~/.config/cantainer` but never write it, so a cant can't change its own or
another cant's manifest.

## Example

```toml
manifest_version = 1
name = "vim"
version = "0.1.0"
description = "Edit the files named on the command line, and only those"

[entrypoint]
path = "vim"
args = ["-n", "-i", "NONE"]

[args]
operands = "rw"

[args.options]
"-c" = "value"
"-S" = "r"

[capabilities]
network = false
unix_sockets = false
fs.ro = ["/usr/share/vim", "/etc/vim", "~/.vimrc", "~/.vim"]
fs.rw = []
exec = []

[env]
pass = ["TERM", "LANG", "LC_*", "HOME"]
```

## Top level

| Field | Required | Meaning |
|---|---|---|
| `manifest_version` | yes | Must be `1`. |
| `name` | yes | 1–64 characters of `[a-z0-9._-]`, starting with a letter or digit. |
| `version` | yes | 1–64 characters of `[A-Za-z0-9.+-]`. |
| `description` | no | One line, at most 512 bytes. |

## `[entrypoint]`

| Field | Required | Meaning |
|---|---|---|
| `path` | yes | An absolute path, or a bare program name. Bare names are looked up in a fixed list of system directories (`/usr/local/bin`, `/usr/bin`, `/bin`, `/usr/local/sbin`, `/usr/sbin`, `/sbin`), **never** in the caller's `$PATH`. |
| `args` | no | Arguments always placed before the user's arguments. |

The program must be a native ELF executable. Scripts (`#!`) are not supported yet.
`argv[0]` is the name as found (`vim`), even when the file is a symlink (`vim.basic`).

## `[args]`: the powerbox

The command line is the permission. This table tells `cant` which arguments name files, so it can
grant exactly those files and nothing else.

| Field | Default | Meaning |
|---|---|---|
| `operands` | `"none"` | How non-option arguments are treated: `"none"` (not files), `"r"` (files or directories to read) or `"rw"` (to read and write). |
| `options` | `{}` | Options that take a value, keyed by spelling (`"-o"`, `"--output"`). The value is `"value"` (not a file), `"r"` or `"rw"`. |

Parsing follows getopt conventions:

- `--` ends the options. Everything after it is an operand.
- `-` alone means stdin or stdout and is never a file grant.
- `--name=value` and `--name value` both work for listed long options.
- `-o value` and `-ovalue` both work for listed short options, including inside clusters (`-sSo out`).
- Options that aren't listed are treated as flags without a value. If such an option actually takes
  a value, that value is treated as an operand. This can only *add* a grant for something you
  typed. It never hides one.

Grants for files named on the command line:

- A file or directory that exists is granted at its **canonical path** (symlinks resolved). A
  directory grant covers everything beneath it.
- A readable file that doesn't exist is not granted. The program reports the missing file itself.
- A writable file that doesn't exist (`vim new.txt`) is **created empty** before the sandbox
  starts, so the kernel has a file to grant. A dangling symlink at that name is refused.
- A path that is, is inside, or contains a [protected path](#protected-paths) is refused before
  launch, even if it doesn't exist.

## `[capabilities]`

| Field | Default | Meaning |
|---|---|---|
| `network` | `false` | May open IP and other non-Unix sockets (TCP, UDP, raw, netlink…). |
| `unix_sockets` | `false` | May open Unix domain sockets, and so reach local services such as D-Bus, `docker.sock` or ssh-agent. |
| `fs.ro` | `[]` | Paths to read: a file, or a whole directory tree. |
| `fs.rw` | `[]` | Paths to read and write: create, modify, rename and delete within. |
| `exec` | `[]` | Programs this cant may execute: absolute paths, directories (everything beneath), or bare names. |

Paths in `fs.ro`, `fs.rw` and `exec` take one of these forms:

- `/absolute/path`
- `~` or `~/relative`: your home directory
- `$CWD` or `$CWD/relative`: the directory `cant` runs in

Relative paths, `~user`, other variables and `.`/`..` components are rejected. Paths that don't
exist are skipped; `--explain` lists them.

The program's own executable, its ELF interpreter and its shared libraries are granted
automatically. So is a small runtime base: the loader cache, locale, time zone and terminfo
data, plus `/dev/null`, `/dev/tty`, `/dev/zero`, `/dev/full`, `/dev/random` and `/dev/urandom`.
Libraries of `exec` targets are resolved for files, but not for directories.

## `[env]`

| Field | Default | Meaning |
|---|---|---|
| `pass` | `[]` | Environment variables that pass through. A trailing `*` matches a prefix (`LC_*`). |

Everything else is removed from the environment. Patterns that could match a dynamic-linker
variable (`LD_*`, `L*`, `*`) are rejected. `cant` always sets `CANT_POLICY` (see
[ARCHITECTURE.md](ARCHITECTURE.md#attenuation)).

## Protected paths

Some paths can't be reached by any manifest grant or command-line file, because Landlock rules
can only add access and a grant on `~` would expose everything inside it:

- **No access:** `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.azure`, `~/.config/gcloud`, `~/.kube`,
  `~/.docker`, `~/.netrc`, `~/.git-credentials`, `~/.config/git/credentials`, `~/.config/gh`,
  `~/.password-store`, `~/.local/share/keyrings`, `~/.pki`, `~/.mozilla`, browser profiles,
  `~/.cargo/credentials(.toml)`, `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials`, shell histories.
- **Read-only:** `~/.config/cantainer`, shell startup files (`~/.bashrc`, `~/.profile`,
  `~/.zshrc`, …), `~/.config/fish`, `~/.config/autostart`, `~/.config/systemd`.

A grant that *contains* one of these is refused too. For example, the `git` example grants
`$CWD`, so running it from your home directory is refused. To reach a protected path deliberately,
name it with `cant run --grant PATH[:ACCESS] ...`. The list is built into `cant`; manifests can't
change it.

## Validation errors

```
$ cant run ./bad.toml
cant: ./bad.toml: invalid manifest:
  - entrypoint.path: `bin/x` is relative; use an absolute path, `~/...` or `$CWD/...`
  - capabilities.fs.ro[1]: `~bob/x`: only `~` and `~/...` are supported, not `~user`
  - env.pass[0]: `LD_PRELOAD` would pass dynamic-linker variables (LD_*), which is not allowed
```
