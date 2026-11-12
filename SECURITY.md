# Security policy

Cantainer is **experimental**. It has not been audited. Don't rely on it as your only defence for
anything that matters.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[security advisories](https://github.com/cantainer/cantainer/security/advisories/new) for this
repository. Don't open a public issue. We'll acknowledge the report, work on a fix with you, and
credit you unless you prefer otherwise.

## Threat model

**What a cant is meant to stop.** A program you choose to run, and anything it starts, that is
buggy, compromised or malicious (a tool driven by an AI agent, a dependency's build script, a
download you don't fully trust) from:

- reading or writing files outside what its manifest and your command line grant;
- reading credentials such as `~/.ssh`, `~/.aws` and `~/.gnupg`, even if a manifest is careless;
- opening network connections when `network = false`;
- connecting to local services over Unix sockets when `unix_sockets = false`;
- gaining rights by running other programs, including `cant` itself;
- using a set of kernel interfaces with a history of exploits (`io_uring`, `bpf`, user namespaces,
  `ptrace` and others; see ARCHITECTURE.md);
- injecting keystrokes into your terminal (`TIOCSTI`).

**What it trusts.**

- **The kernel.** Landlock and seccomp are only as strong as the kernel that enforces them. A
  kernel exploit escapes the sandbox.
- **The manifest.** A manifest that grants `network = true` and `fs.rw = ["~/src"]` is honoured.
  Read manifests before you install them. Protected paths are the exception: no manifest can
  reach them.
- **You, at launch.** Files you name on the command line are granted. That is the design.
- **`cant` itself and the files it reads before restricting itself.**

## Known limitations

These are current gaps. Most are kernel limits, and some are planned work.

- **No sandbox below Landlock ABI 3** (Linux 6.2). `cant` refuses to run there. `cant check`
  tells you what your kernel supports.
- **Metadata reads aren't hidden.** A cant can `stat()` any path, so it learns that
  `~/.ssh/id_rsa` exists, its size and its timestamps, though not its contents. It can't list
  directories it has no read grant for.
- **Signals** to other processes of the same user are only blocked on kernels with Landlock ABI 6
  or later (Linux 6.12).
- **Abstract Unix sockets** are only blocked by Landlock ABI 6+ scoping. With
  `unix_sockets = false` seccomp blocks Unix socket creation altogether, so this matters only
  for cants granted Unix sockets.
- **Pathname Unix sockets:** a cant with `unix_sockets = true` can connect to any Unix socket
  whose path it can reach, unless the kernel has Landlock ABI 9.
- **Inherited file descriptors.** Files and sockets that are already open when `cant` starts
  (stdin, stdout, stderr, anything else the caller passes) stay usable. Landlock checks access
  when a file is opened, not when it is used.
- **Hard links.** A pre-existing hard link to a protected file, placed in a granted directory, is
  reachable, because Landlock grants are per inode. A cant can't create such links itself.
- **Time-of-check races.** `cant` canonicalizes paths, then opens them to build the Landlock
  rules. A process of the same user that swaps directories in between could redirect a grant. If
  such a process exists, it already has your rights.
- **Manifests you install are trusted.** `cant run NAME` uses `~/.config/cantainer/cants`, then
  `/etc/cantainer/cants`, then the built-in manifests. Anything that can write those directories
  outside a cant (you, root) decides what a name may do. Cants themselves can't write them.
- **The dynamic loader runs any readable ELF file.** A cant running a dynamically linked
  program (or allowed to execute a directory) may execute the system's dynamic loader, and
  `ld.so ./file` runs any ELF file the cant can read, even one it has no execute grant for.
  Landlock checks execute rights when a file is executed, not when it is mapped. The program
  still has only the cant's rights.
- **`dlopen`ed libraries** aren't discovered automatically. Plugins fail to load unless the
  manifest grants them; this fails closed.
- **seccomp is a deny list.** System calls not listed are allowed, and Landlock is the primary
  filesystem control. Architectures other than x86_64, aarch64 and riscv64 are unsupported.
- **`CANT_POLICY` is informational.** A cant can forge it to change what a nested `cant` prints,
  but not what the kernel enforces.
