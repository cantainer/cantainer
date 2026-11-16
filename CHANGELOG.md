# Changelog

All notable changes to Cantainer are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, any release may contain breaking changes.

Security-relevant changes are listed under **Security**.

## [Unreleased]

## [0.0.4] - 2026-11-16

### Security
- More home paths are read-only for every cant, because writing them runs code outside the
  sandbox later: `~/.gitconfig`, `~/.config/git`, `~/.local/bin`, `~/bin`, `~/.vimrc`,
  `~/.config/nvim`, `~/.cargo/config.toml`, `~/.config/environment.d`. Read-only protected
  paths stay readable and executable, so a `~/bin` program still runs.
- The offline `cargo` cant can no longer write `~/.cargo/registry` or `~/.cargo/git`, so a build
  script can't tamper with other crates' sources. Only `cargo-net` writes them.
- `cargo` and `cargo-net` can no longer write `.git`, `.envrc`, `.vscode`, `.idea` or
  `.githooks` in the project directory (build scripts could plant hooks there). They grant the
  project's existing entries one by one (`fs.rw = ["$CWD/*"]`) and create `target/` and
  `Cargo.lock` themselves (`fs.ensure_dirs`, `fs.ensure_files`).
- **Watched cants:** cants that may write the project directory (`git`, `cargo`, `agent-sh`)
  run under a supervisor that compares `.git/config`, git hooks, `.envrc`, `.vscode` and
  similar files before and after the run, including what detached processes did. A change is
  reported with a session ID; nothing is reverted automatically. Processes still running two
  seconds after the program exits are stopped. This is detection with a window, not
  prevention; see SECURITY.md.

### Added
- `cant diff ID`, `cant revert ID`, `cant keep ID`, `cant log` and `cant verify`: review, undo or
  accept what a watched cant changed. `cant revert` refuses files that changed again since and
  never writes through symlinks. A cant can't accept its own changes.
- Manifests: `fs.rw = ["$CWD/*"]`, `fs.ensure_dirs` and `fs.ensure_files`.
- **Cans (experimental, unsigned):** redistributable cants that carry their own libraries,
  libc and ELF loader included, so one built on one distribution runs on another.
  `cant pack NAME` makes one (an OCI image layout directory with a CycloneDX SBOM),
  `cant run ./NAME.can` runs it, `cant push`/`cant pull` move it through OCI registries, and
  `cant run HOST/NAME:TAG` runs a pulled can. Cans aren't signed yet: a can from a registry
  runs only after you pull it yourself. Design: docs/CANS.md; format: spec/can-format.md.
- Manifest version 2 for cans: `$CAN` paths and `[pack]`.

### Changed
- Building for other architectures needs a C compiler for the target: the registry client's
  TLS (rustls with ring) contains C and assembly. See docs/ARCHITECTURE.md.
- The `cant` binary is larger (about 9 MB instead of 3 MB) because of the registry client;
  `cant run` starts as fast as before.

### Fixed
- The Homebrew formula failed to load on macOS (`formula requires at least a URL`) instead of
  saying that Cantainer needs Linux.

### Known limitations
- In a can, programs that check `/proc/self/exe` refuse to run, because a can's program starts
  through its bundled loader. Ubuntu 26.04's coreutils (uutils) are such programs.
- `git config` and other commands that rewrite `.git/config` fail in the `git` cant (git sets
  the lock file's permissions by path, which the sandbox refuses).

## [0.0.3] - 2026-11-12

0.0.2 was tagged but never published: its aarch64 release build failed. Its changes ship in
0.0.3.

### Added
- Release process: `dev/release.sh`, a tag-triggered release workflow with an approval gate,
  crates.io Trusted Publishing, and prebuilt static `cant` binaries for x86_64 and aarch64 Linux
  with signed SHA-256 checksums. `cargo binstall cantainer` downloads them.
- Packages: `.deb` and `.rpm` packages, signed APT and RPM repositories at
  <https://cantainer.github.io/packages/>, and a Homebrew tap (`cantainer/tap/cantainer`).
  The AUR package `cantainer-bin` is prepared and follows once AUR registration reopens.

- Built-in cants for everyday tools: `cat`, `head`, `tail`, `wc`, `diff`, `sed`, `jq`, `grep`,
  `rg`, `find`, `ls`, `tree`, `git`, `vim`, `curl` (no network) and `curl-net`. Each has a
  sandbox test showing it works and can't reach `~/.ssh`.
- Manifests are built into `cant`, so every installation can run them by name.
  Lookup order: `~/.config/cantainer/cants`, then `/etc/cantainer/cants` (new), then built in.
- `cant show NAME` prints a manifest, for example to copy and customize it.
- `cant list` shows where each manifest comes from.
- `cant new PROGRAM` writes a commented, deny-everything manifest to fill in.
- Manifests: `[args] value_operands` and `value_operands_unless` for programs whose first
  operand is a pattern, filter or script rather than a file (`grep`, `rg`, `jq`, `sed`).
- Manifests: `entrypoint.path` may be `~/...` (tools installed in your home), and
  `[env] set` sets variables to fixed values (`$CWD` and `~` expand).
- `capabilities.cants = [...]`: a cant may run these cants, and its rights include theirs, so
  nested `cant run` works. Running an unlisted cant inside another fails with a clear message.
- Built-in `cargo` (offline) and `cargo-net` (for `cargo fetch`): build scripts, proc macros
  and tests run sandboxed, so a malicious dependency can't read `~/.ssh` or, offline, reach the
  network. Tested with a build script that tries to read a key.
- Built-in `agent-sh`: a shell for AI agents that works in the current directory, has no
  network, and runs tools as cants. Guide: `docs/AGENTS.md`.
- `cant completions bash|zsh|fish|elvish|powershell`, and man pages. Packages and the Homebrew
  formula install both.

### Changed
- The example manifests moved from `examples/` to `crates/cantainer/cants/`.

### Removed
- **Breaking:** `cant run NAME` no longer looks in `./examples/`. Use a path
  (`cant run ./examples/x.toml`) or put the manifest in `~/.config/cantainer/cants/`.

### Fixed
- Programs linked by GNU ld inside a cant (Rust on aarch64, C everywhere) came out without the
  executable bit, because path-based `chmod` was refused. Manifests can now declare
  `capabilities.chmod_by_path`, limited to modes within `0775`; `cargo` and `cargo-net` do.
- `cant-launch` builds for aarch64 with musl and for riscv64 (it used a syscall constant the
  `libc` crate doesn't define there).
- A static program in a cant (rustup on arm64) can start dynamically linked programs from an
  `exec` directory: such cants now get execute access to the dynamic loaders.
- `cant list | head` and similar no longer panic when the reader closes the pipe.
- Landlock rule paths are opened with `O_PATH` through `rustix` instead of `landlock::PathFd`.
  On musl, Rust's std strips `O_PATH`. Every granted path was then really opened, so `cant`
  failed with "No such device or address" when there was no controlling terminal (for
  `/dev/tty`), and would have blocked on a FIFO.

### Security
- A repository's `./examples/` directory can no longer choose the manifest for a name you run
  inside it.

## [0.0.1] - 2026-11-12

First release.

### Added
- `cant run`: runs a cant under Landlock (deny-by-default filesystem, TCP when the network is off,
  signal and abstract-socket scopes on newer kernels) and seccomp, then `exec`s the program. Exit
  status, signals and the terminal are the program's own. `--explain` prints the effective policy;
  `--grant PATH[:ACCESS]` adds a grant.
- Powerbox: files named on the command line are granted as the manifest's `[args]` declares.
- Protected paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, credentials, shell startup files, …) that no
  manifest or command-line file can reach without `--grant`.
- Attenuation: a nested `cant` gets the intersection of its own and the enclosing cant's rights,
  enforced by the kernel and explained via `CANT_POLICY`.
- `cant inspect`, `cant list`, `cant check`.
- Strict TOML manifests (`docs/MANIFEST.md`) and examples for `cat`, `curl`, `git` and `vim`.
- Crates: `cantainer`, `cant-manifest`, `cant-policy`, `cant-launch`, `cant-store`.

### Security
- Baseline seccomp filter: refuses `ptrace`, `io_uring`, `bpf`, namespace creation, mounts,
  path-based metadata changes, `TIOCSTI`, x32 syscalls, and sockets the policy doesn't allow.
- Refuses to run on kernels below Landlock ABI 3.

[Unreleased]: https://github.com/cantainer/cantainer/compare/v0.0.4...HEAD
[0.0.4]: https://github.com/cantainer/cantainer/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/cantainer/cantainer/compare/v0.0.1...v0.0.3
[0.0.1]: https://github.com/cantainer/cantainer/releases/tag/v0.0.1
