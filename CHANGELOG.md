# Changelog

All notable changes to Cantainer are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0, any release may contain breaking changes.

Security-relevant changes are listed under **Security**.

## [Unreleased]

### Added
- Release process: `dev/release.sh`, a tag-triggered release workflow with an approval gate,
  crates.io Trusted Publishing, and prebuilt static `cant` binaries for x86_64 and aarch64 Linux
  with signed SHA-256 checksums. `cargo binstall cantainer` downloads them.
- Packages: `.deb` and `.rpm` packages, signed APT and RPM repositories at
  <https://cantainer.github.io/packages/>, and a Homebrew tap (`cantainer/tap/cantainer`).
  The AUR package `cantainer-bin` is prepared and follows once AUR registration reopens.

- Manifests are built into `cant`, so every installation can run `cat`, `git`, … by name.
  Lookup order: `~/.config/cantainer/cants`, then `/etc/cantainer/cants` (new), then built in.
- `cant show NAME` prints a manifest, for example to copy and customize it.
- `cant list` shows where each manifest comes from.
- `cant new PROGRAM` writes a commented, deny-everything manifest to fill in.
- `cant completions bash|zsh|fish|elvish|powershell`, and man pages. Packages and the Homebrew
  formula install both.

### Changed
- The example manifests moved from `examples/` to `crates/cantainer/cants/`.

### Removed
- **Breaking:** `cant run NAME` no longer looks in `./examples/`. Use a path
  (`cant run ./examples/x.toml`) or put the manifest in `~/.config/cantainer/cants/`.

### Fixed
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

[Unreleased]: https://github.com/cantainer/cantainer/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/cantainer/cantainer/releases/tag/v0.0.1
