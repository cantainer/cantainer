# Architecture

This document records how Cantainer works, the decisions behind it, and the alternatives we
rejected. Update it when a decision changes.

## Crates

```
cantainer      `cant` binary: argument parsing, manifest lookup, output. Thin.
  ├─ cant-manifest   TOML types and strict validation. No I/O except reading the file.
  ├─ cant-policy     What is allowed: access model, powerbox, protected paths, attenuation,
  │                  building a Policy from manifest + command line. Pure logic plus path
  │                  canonicalization; fully unit-tested, portable.
  ├─ cant-launch     How it is enforced: ELF library resolution, Landlock, seccomp, exec.
  │                  Linux-only internals behind cfg; stub errors elsewhere.
  └─ cant-store      Content digests (used by `inspect`) and the future store interface.
```

The split keeps the security decisions (`cant-policy`) separate from the kernel mechanics
(`cant-launch`). The policy code can then be tested exhaustively, including property tests,
without a sandbox-capable kernel, and the launcher stays small enough to audit.

## The run path

```
cant run vim notes.txt
  1. locate manifest      ~/.config/cantainer/cants/vim.toml, /etc/cantainer/cants/vim.toml,
                          then the built-in vim manifest
  2. validate             cant-manifest (strict; all problems reported)
  3. build policy         cant-policy::build
       --grant paths      (unlock protected paths explicitly)
       executable         rx on its canonical path
       manifest fs/exec   resolved (~, $CWD), canonicalized; missing paths skipped
       powerbox           files named in argv per [args]; refused if protected
  4. plan                 cant-launch::plan
       ELF interpreter + shared libraries (+ exec targets' libraries)
       runtime base (ld.so.cache, locale, terminfo, /dev/null, /dev/tty, ...)
       attenuation against CANT_POLICY if nested; filtered env; argv
  5. --explain?           print plan.effective and stop
  6. enforce              create pending rw files → Landlock restrict_self → seccomp
  7. execve               the program replaces cant; exit status, signals, TTY are its own
```

## Decisions

### Enforcement: Landlock + seccomp, no namespaces

Landlock gives unprivileged, path-based access control that is inherited across `exec` and can
only be tightened. seccomp covers what Landlock does not. Together they need neither root nor
user namespaces, and they add about 1.4 ms to a launch (see README).

*Rejected:* mount namespaces with bind mounts (bubblewrap-style). They need user namespaces,
which Ubuntu 24.04 restricts for unprivileged users by default. They also add startup cost and
complicate TTY and job control. Namespaces remain an option for features Landlock can't express,
such as hiding paths entirely.

### No supervisor: `cant` execs the program

`cant` restricts itself and calls `execve`. Nothing stays behind, so exit codes, signals,
job control (`^Z`) and the terminal behave exactly as without `cant`.

*Consequence:* Landlock returns `EACCES` without telling an unprivileged process which path was
refused, so `cant` can't print a branded message for denials that happen at runtime. Branded
messages (`cant: cat can't read ~/.ssh/id_rsa (...)`) cover pre-launch refusals; runtime denials
appear as the program's own "Permission denied". `--explain` shows the policy.

*Rejected:* staying as a parent process to print hints after failures. That means signal
forwarding and process-group handling for little gain, since the parent still doesn't know which
path was refused.

`cant` uses exit status 125 for its own refusals and errors (like `env` and container
runtimes), 126 if the program can't be executed, and 127 if it isn't found.

### Protected paths

Landlock rules can only add access; there are no deny rules. Granting `~` would therefore expose
`~/.ssh`. `cant-policy` keeps a built-in list of secrets (no access) and persistence points
(read-only). It refuses any implicit grant (manifest or command-line file) that is, is inside, or
contains one of them, even if the path doesn't exist yet. Symlinks are resolved first, so
`ln -s ~/.ssh/id_rsa x; cant run cat x` is refused too. Only `--grant PATH` unlocks a protected
path, and only for the access it names.

This is also what makes the demo's `cant run cat ~/.ssh/id_rsa` fail even though `cat` declares its
operands readable: the command line is the permission, except for paths a user would never mean
to hand over implicitly.

*Rejected:* only granting command-line paths under the current directory. That is simpler, but it
breaks `cat /etc/os-release` and doesn't stop a manifest's own grants from covering secrets.

### Network: seccomp first, Landlock second, no network namespace

`network = false` is enforced by a seccomp rule that refuses `socket()` for every non-Unix address
family. That covers TCP, UDP (so DNS fails, which is what you see from curl), raw and netlink
sockets, on every kernel. When the kernel's Landlock ABI is ≥ 4, Landlock TCP bind/connect rules
are added as a second layer. Below ABI 4, `cant` prints a note that only seccomp applies.

*Rejected:* falling back to a network namespace, as the original brief suggested. The seccomp
rule already blocks everything a namespace would, without user namespaces. The fallback would
never be needed.

### Unix sockets are a separate capability

Landlock before ABI 9 can't stop `connect()` to a pathname Unix socket, so a cant with network off
could still talk to `docker.sock`, D-Bus or ssh-agent. `unix_sockets = false` (the default) makes
seccomp refuse `socket(AF_UNIX)`. `socketpair()` stays allowed because it creates no reachable
endpoint. On newer kernels Landlock also scopes abstract Unix sockets (ABI 6), and pathname socket
connects (ABI 9) are added best-effort.

### seccomp baseline

The baseline is a deny list on top of Landlock, not an allow list, so unmodified programs work.
It refuses:

- debugging and cross-process memory access: `ptrace`, `process_vm_*`;
- kernel and system state: modules, kexec, reboot, swap, clocks, `syslog`, `acct`, `quotactl`;
- large attack surface: `bpf`, `perf_event_open`, `userfaultfd`, keyrings, and `io_uring`
  (it can open files and sockets without the syscalls filtered here);
- namespaces and mounts: `unshare`, `setns`, `mount` and the new mount API, `pivot_root`,
  `chroot`, and `clone` with any `CLONE_NEW*` flag;
- file handles: `open_by_handle_at`, `name_to_handle_at`;
- path-based metadata changes, which Landlock does not control: `chmod`, `fchmodat(2)`,
  `chown`/`lchown`/`fchownat`, `*setxattr`/`*removexattr` on paths, `utime(s)`, `futimesat`, and
  `utimensat` with a path. The fd-based variants stay allowed because they need a file the cant
  could already open. vim and git work with this.
- terminal injection: `ioctl(TIOCSTI)` and `ioctl(TIOCLINUX)`.

`clone3` returns `ENOSYS`: its flags are in memory seccomp can't read, and glibc falls back to
`clone`, whose flags *can* be checked. On x86_64, a hand-written guard filter refuses x32 syscall
numbers (`nr ≥ 0x40000000`). They share the x86_64 audit arch, and seccompiler only checks the
arch, so a number-based deny list wouldn't see them otherwise.

### Minimum Landlock ABI 3

Below ABI 3 (Linux 6.2), `truncate` isn't controlled, so a read-only grant wouldn't stop a cant
from emptying a file. `cant` refuses to run instead of pretending. The ruleset targets the newest
ABI the `landlock` crate knows (9) on a best-effort basis: rights the kernel doesn't support are
dropped, except that the ABI ≥ 3 floor is checked. The exact ABI comes from `RestrictionStatus`,
because the crate has no public probe; `cant check` applies a no-op ruleset to itself to learn it.

### Libraries: our own ELF reader

Deny-by-default means the loader and every shared library must be granted. `cant-launch` reads
`PT_INTERP` and the `DT_NEEDED`/`DT_RPATH`/`DT_RUNPATH` entries with a few bounds-checked
positioned reads per file. It then searches like glibc: RPATH (without RUNPATH), RUNPATH with
`$ORIGIN`, the directories in `/etc/ld.so.conf`, then the system defaults. `glibc-hwcaps`
variants are included. The interpreter gets `rx`; libraries get `r` (Landlock's execute right
governs `execve`, not `mmap`).

*Rejected:* `goblin`, which needs the whole file in memory (megabytes per launch for large
programs). Also rejected: running `ldd`/`ld.so --list`, which costs a process per launch and
executes the loader against the target. Granting all of `/usr/lib` was rejected as too broad.

*Limitations:* `ld.so.cache`, `$LIB`/`$PLATFORM` and `dlopen()`ed modules aren't resolved. Add
the latter to `fs.ro` in the manifest. Libraries of `exec` targets given as directories aren't
resolved (so git's HTTPS helper can't load libcurl in the example; it would have no network
anyway).

### Bare program names use a fixed search path

`entrypoint.path = "vim"` is resolved in `/usr/local/bin`, `/usr/bin`, `/bin` and the `sbin`
equivalents, never in `$PATH`. In the situations a sandbox exists for, `$PATH` is controlled by
whoever wants out.

### Writable files that don't exist yet

Landlock grants attach to existing inodes. For `vim new.txt` with `operands = "rw"`, `cant` creates
`new.txt` empty with `O_CREAT|O_EXCL` (which won't follow a planted symlink) right before
applying the rules. *Rejected:* granting the parent directory, which would expose every sibling.

### Environment

Only variables matching `[env] pass` reach the program. Patterns that could match `LD_*` are
rejected at validation time.

### Attenuation

When a cant runs `cant run other`, the inner `cant` adds a new Landlock domain and new seccomp
filters on top of the inherited ones. The kernel enforces the intersection: rights can only
shrink. `cant-policy::intersect(parent, child)` computes the same intersection. A property test
checks that `intersect(p, c).permits(x, a) == p.permits(x, a) && c.permits(x, a)` for random
policies, paths and rights.

`cant` puts its effective policy in `CANT_POLICY` (TOML). A nested `cant` uses it to:

- refuse early, with a clear message, when the user names a file the enclosing cant can't access
  (`cat can't read ~/proj/notes.txt (not granted by the enclosing cant)`);
- show the intersection in `--explain`.

The value is informational. A cant that forges it can only change what the nested `cant` prints,
never what the kernel allows.

### Manifest lookup

Order: `~/.config/cantainer/cants/` (the user), `/etc/cantainer/cants/` (the administrator),
then the manifests compiled into `cant` from `crates/cantainer/cants/`. The first match wins.

**Built in, not installed as files.** `cargo install` and `cargo binstall` install only the
binary, so a data directory (`/usr/share/cantainer/cants`, or one found relative to the
executable) would leave those installations without manifests, and finding it relative to the
executable is fragile across packaging layouts. Compiling them in costs a few kilobytes and
keeps each manifest in step with the `cant` that understands its format. Packages create an
empty `/etc/cantainer/cants` for administrators.

**Rejected: the current directory.** 0.0.1 fell back to `./examples/`. That let a repository you
`cd` into choose the manifest for a name such as `git`: it couldn't reach protected paths, but
it could grant itself the network or more of the file system. Removed in 0.0.2; a path such as
`cant run ./cants/x.toml` is still explicit.

## Where the code is

| Concern | File |
|---|---|
| Manifest types and validation | `crates/cant-manifest/src/lib.rs` |
| Access rights | `crates/cant-policy/src/access.rs` |
| Policy, `intersect` | `crates/cant-policy/src/policy.rs` |
| Powerbox argument parsing | `crates/cant-policy/src/powerbox.rs` |
| Protected paths | `crates/cant-policy/src/protect.rs` |
| Building a policy | `crates/cant-policy/src/build.rs` |
| ELF library resolution | `crates/cant-launch/src/linux/elf.rs` |
| Landlock | `crates/cant-launch/src/linux/landlock.rs` |
| seccomp | `crates/cant-launch/src/linux/seccomp.rs` |
| Plan and exec | `crates/cant-launch/src/linux/mod.rs` |
| CLI | `crates/cantainer/src/main.rs` |
