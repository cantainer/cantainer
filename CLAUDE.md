# Cantainer: project brief

This file is the project's source of truth for goals, constraints and working rules.
Keep it current. Move decisions into `docs/ARCHITECTURE.md` once they are made.

## What Cantainer is

Cantainer runs every executable as a lightweight **capsule** (one capsule is "a cant"). Each cant has
its own content-addressed identity, its own dependency closure, and a declared set of capabilities.
The kernel enforces those capabilities using Landlock, seccomp and namespaces. You run cants like
ordinary commands, with near-native startup, no daemon and no root.

- **Crate name:** `cantainer` · **CLI binary:** `cant` (`cant run vim`, `cant inspect git`)
- **Tagline:** "By default, you can't."
- **README joke to keep:** "There is no cantainerd. No daemon. You cant."
- **Error voice:** `cant: vim can't write ~/.ssh/config (not granted)`

### What makes it different
1. **The unit is the executable.** Not an app (Flatpak) or an environment (Docker).
2. **Unmodified native Linux binaries.** Unlike WASI, nothing needs recompiling.
3. **Attenuation across exec.** When cant A runs cant B, B gets `intersect(A granted, B declared)`.
   Rights only shrink down the chain.
4. **Powerbox file grants.** The launcher grants exactly the files named on the command line
   (`vim notes.txt` → only `notes.txt`). The command line is the permission: no prompts, no `allow *`.
5. **OCI-native distribution, file-level dedup.** OCI registries as transport; storage is
   content-addressed per file (composefs/fs-verity later), not tar layers.
6. **First killer use case: AI agents running tools safely.** An agent may run `git` and `cargo`,
   but can't read `~/.ssh` or reach the network.

### Long-term vision (not now)
A minimal Linux OS with no shared userland: no `/usr/bin`, every command (even `ls`, `sh`) is a cant.
**The runtime ships first, as a standalone tool on ordinary Linux.**

Roadmap, out of scope for now (list in `docs/VISION.md`): OCI registry pull/push, composefs store,
sigstore signing, cached sandboxes, shell integration, bootable OS image, Docker/Kubernetes integration.

## Hard constraints
- **Rust only.** Edition 2024, stable toolchain. `#![forbid(unsafe_code)]` everywhere except small,
  documented syscall shims (prefer `rustix` so there are none).
- **Linux only at runtime.** The maintainer develops on macOS: keep a Lima/OrbStack VM config and
  `.devcontainer/`, both with kernel ≥ 6.7 (Landlock ABI v4 network rules). Document the macOS
  build/test path exactly.
- **Must compile on macOS** for editing: gate Linux modules with `cfg(target_os = "linux")` and
  return stub errors elsewhere. Tests run on Linux.
- **No daemon, no root** for the core path. User namespaces only where needed.
- **Verify crate names, versions and APIs** on crates.io and docs.rs before using them; never rely on
  memory. Candidates: `rustix`, `landlock`, `seccompiler`, `oci-spec`, `oci-client`, `clap`,
  `serde`/`toml`, `thiserror`/`anyhow`, `tracing`. Study `youki` for namespace/mount patterns, but
  don't depend on it.
- **License:** dual MIT/Apache-2.0.

## Milestone 0 → early Milestone 1 scope

### Workspace layout
```
Cargo.toml                 # workspace
crates/
  cantainer/               # published crate: `cant` binary (thin CLI)
  cant-manifest/           # Cantfile / manifest types + validation
  cant-launch/             # sandbox setup + exec (Landlock, seccomp, namespaces)
  cant-policy/             # capability model, attenuation, powerbox arg grants
  cant-store/              # stub: content-addressed store interface (later composefs)
examples/                  # sample manifests (cat, curl, git, vim)
docs/                      # VISION.md, ARCHITECTURE.md, MANIFEST.md
dev/                       # lima.yaml, scripts
.devcontainer/
.github/workflows/ci.yml   # fmt, clippy -D warnings, test, Landlock integration tests
```

### Features
1. **Manifest (TOML):** name, version, entrypoint, args schema (which positional args are files,
   `r`/`rw`), capabilities (fs paths ro/rw, network on/off, allowed exec targets), env passthrough
   allowlist. Strict validation. Documented in `docs/MANIFEST.md`.
2. **`cant run <name|path-to-manifest> [args...]`:** resolve from `~/.config/cantainer/cants/` and
   `./examples/` (no registry yet). Landlock deny-by-default, then allow manifest paths, the binary
   and its libs, plus powerbox grants for declared file args. Landlock network rules when supported,
   else warn clearly and fall back to a network namespace. Baseline seccomp filter. `exec` the real
   binary; pass exit codes through; keep stdin/stdout/stderr and TTY intact (vim must work).
3. **Clear denial messages** in the brand voice; `--explain` shows the effective policy.
4. **`cant inspect <name>`:** manifest, resolved binary path, sha256 digest, effective capabilities.
5. **Attenuation:** `effective = intersect(parent_granted, child_declared)` as a tested library
   function. Wire into exec only if clean; otherwise TODO + design note.
6. **Startup benchmark:** `cant run cat` vs `cat`, 1k runs, in `benches/` or a script. Record the
   measured result in the README. Target: low single-digit ms overhead. Measure, don't guess.

### Demo (acceptance test + vhs/asciinema script for the README GIF)
```
cant run cat ~/.ssh/id_rsa        # denied: not granted
cant run cat notes.txt            # works: powerbox grant
cant run curl https://example.com # denied: no network capability
cant run vim notes.txt            # vim works, can only touch notes.txt
```

## Quality bar
- `cargo fmt`, `cargo clippy --all-targets -- -D warnings`, `cargo test` all clean.
- CI green on GitHub Actions (ubuntu-latest), plus a job that checks the kernel's Landlock ABI and
  skips sandbox tests gracefully if missing.
- Unit tests for manifest validation and policy intersection; Linux-gated integration tests for the sandbox.
- README: pitch, quickstart (incl. Mac → Lima), demo, benchmark numbers, "status: experimental",
  and an honest (not hype) comparison with Docker, Flatpak, Nix, bubblewrap, pkgx and WASI.
- CONTRIBUTING.md; SECURITY.md honest about the threat model and current limitations.
- Keep `docs/ARCHITECTURE.md` updated with decisions and rejected alternatives.

## Publishing
Prepare `crates/cantainer` to publish as `cantainer` 0.0.1 with real, working functionality
(the `cant-*` dependency crates must be published too, or merged in).

## How to work on this project
- Propose a plan and wait for the maintainer's OK before building larger pieces.
- When a library or kernel limitation forces a design change, **stop and say so**; never work
  around it quietly.
- Prefer boring, explicit code. This is security software: correctness and clear errors beat cleverness.
- Commit in small, logical steps with clear messages.
- **Never run `cargo publish` or push to the remote without asking first.**

## Design decisions (settled 2026-11-11)
The maintainer accepted all recommendations. Move these into `docs/ARCHITECTURE.md` when it exists.

1. **Protected paths.** A built-in list (`cant-policy/src/protect.rs`) is never reachable by an
   implicit grant (manifest or powerbox): secrets (`~/.ssh`, `~/.gnupg`, `~/.aws`, …) get no access,
   persistence points (`~/.bashrc`, `~/.config/cantainer`, …) are read-only. A grant that *contains*
   a protected path (e.g. `$CWD` = home) is refused too, because Landlock has no deny rules.
   `--grant PATH[:r|rw]` is the explicit override.
2. **exec model.** `cant` restricts itself and `exec`s the program; no parent process. Branded
   denials (`cant: cat can't read ~/.ssh/id_rsa (...)`) only for pre-launch refusals; `--explain`
   prints the effective policy (dry run). Exit code 125 for cant's own refusals.
3. **Network.** seccomp is the primary control: `network = false` refuses `socket()` for every
   non-Unix family (covers UDP/DNS/raw, works on every kernel, no user namespace). Landlock TCP
   rules are a second layer when ABI ≥ 4. **No netns fallback** (it's never needed with seccomp,
   and Ubuntu 24.04 restricts unprivileged user namespaces). Warn when ABI < 4.
4. **No namespaces at all** in the core path.
5. **Libraries.** Own bounds-checked ELF reader (`cant-launch/src/linux/elf.rs`, positioned reads
   only; goblin was dropped because it needs the whole file). Grants: interpreter rx, libs r,
   glibc-hwcaps variants, plus a small runtime base and manifest `fs.ro`.

Found while designing (also settled):
- **Unix sockets:** Landlock < ABI 9 can't stop `connect()` to pathname sockets (docker.sock,
  D-Bus). New manifest capability `unix_sockets` (default false); seccomp refuses `socket(AF_UNIX)`
  unless granted. Landlock `ResolveUnix` and abstract-socket/signal scopes are added best-effort.
- **Metadata:** Landlock doesn't control chmod/chown/xattr/utimes. Baseline seccomp refuses the
  path-based variants (fd-based ones stay allowed). Verify vim and git still work; if not, add a
  manifest opt-in.
- **x32 bypass:** seccompiler only checks the arch, so x86_64 needs an extra hand-written guard
  filter refusing `nr >= 0x40000000`. `clone3` → ENOSYS (glibc falls back to inspectable `clone`).
- **Minimum Landlock ABI 3** (kernel 6.2): below that `truncate` isn't controlled. Refuse to run.
  Detect the exact ABI from `RestrictionStatus.landlock` (the crate has no public probe).
- **Attenuation:** kernel stacking (Landlock + seccomp) enforces it. `cant` passes its effective
  policy to children in `CANT_POLICY` (TOML) for display/pre-flight only; a forged value can't widen
  real rights.
- **Writable file args that don't exist** are created empty (`create_new`, refuses dangling symlinks)
  so Landlock has an inode to grant.
- **Bare program names** resolve via a fixed system dir list, never the caller's `$PATH`.

## Status (2026-11-11)
Done and pushed: workspace + licenses, `cant-manifest` (+ examples cat/curl/git/vim),
`cant-policy` (access, powerbox, protected paths, `intersect` with property tests, `build`),
`cant-store` (`Digest`, `Store` trait stub), WIP `cant-launch` ELF resolver (not wired in).

Next, in order:
1. `cant-launch`: `linux/landlock.rs` (access mapping, scopes, ABI ≥ 3 check), `linux/seccomp.rs`
   (EPERM filter, clone3 ENOSYS filter, x32 guard), runtime base grants, env filtering, create
   pending files, `exec`; non-Linux stub errors. Run `cargo clippy` (not yet run on any crate).
2. `cantainer` CLI: `cant run [--explain] [--grant ...] <cant> [args]`, `cant inspect`, `cant check`.
   Manifest lookup: `~/.config/cantainer/cants/`, then `./examples/`.
3. Integration tests (Linux-gated, hermetic HOME, skip without Landlock): the four demo commands,
   local TCP listener for the curl test, `vim -es` for the vim test, nested-cant attenuation.
4. `benches/startup.sh` (hyperfine, 1k runs) and record numbers in README.
5. CI (`fmt`, `clippy -D warnings`, tests, Landlock ABI job, `cargo check` on macOS), docs
   (README, VISION, ARCHITECTURE, MANIFEST, SECURITY, CONTRIBUTING), `dev/lima.yaml`
   (Lima ≥ 2.0 `base: template:ubuntu-24.04`, writable home mount), `demo/demo.tape`.
6. `cargo publish --dry-run` for all five crates (ask before publishing).

Repo note: `.git/hooks` has Git LFS hooks but git-lfs isn't installed, so `git push` fails;
pushes so far used `--no-verify`. Fix by installing git-lfs or deleting the hooks.
