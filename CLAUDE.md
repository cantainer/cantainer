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
crates/cantainer/cants/    # built-in manifests (were examples/ until 0.0.2)
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
- Push each commit to `main` (the maintainer asked for small commits and pushes, 2026-11-11).
- **Never run `cargo publish` without asking first.**

## Design decisions
Recorded in `docs/ARCHITECTURE.md` (decisions and rejected alternatives); keep it current.
Highlights: Landlock + seccomp, no namespaces, no supervisor (`exec`), protected paths with
`--grant` override, seccomp-first network blocking (no netns fallback), `unix_sockets`
capability, path-based metadata syscalls blocked, x32 guard, minimum Landlock ABI 3, own ELF
reader, attenuation via kernel stacking + `CANT_POLICY`.

## Status (2026-11-12)
Milestone 0 is implemented and pushed: all five crates, `cant run/inspect/list/check`,
`--explain`, `--grant`, attenuation wired into nested `cant`, 13 sandbox integration tests,
CI (lint, test, sandbox, macOS), docs, Lima config, vhs tape, benchmark (~1.4 ms overhead).
Published 2026-11-12: `cantainer`, `cant-manifest`, `cant-policy`, `cant-launch`, `cant-store`
0.0.1 on crates.io (tag `v0.0.1`). The maintainer ran `cargo publish` from the codespace with the
`CRATES_TOKEN` secret.

Release process (2026-11-12, see `docs/RELEASING.md`): `dev/release.sh` + tag-triggered
`.github/workflows/release.yml` with the `release` environment as approval gate. Channels:
crates.io (Trusted Publishing), GitHub release (static musl binaries, .deb, .rpm, signed
SHA256SUMS), signed APT/RPM repos in `cantainer/packages` on Pages, Homebrew tap
`cantainer/homebrew-tap`, AUR `cantainer-bin`. External setup is done except the AUR.

Open items:
- Cut 0.0.2 through the release workflow (first real run; ask before pushing the tag). After it
  succeeds, the maintainer revokes the `CRATES_TOKEN` crates.io token and deletes the secrets.
- AUR: registration was closed on 2026-11-12. When it reopens: account, SSH key, secret
  `AUR_SSH_KEY` (steps in `docs/RELEASING.md`).
- Distro submissions (each needs the maintainer's OK before any external PR or issue):
  nixpkgs, Alpine, then Fedora review and Debian ITP (including the landlock and seccompiler
  crates), homebrew-core later.
- Package signing key expires 2029-11-11.
- Render `demo/demo.gif` with vhs (not installed in the dev container) and add it to the README.
- `dev/lima.yaml` has not been tested on a Mac yet.
- Git LFS hooks in `.git/hooks` without git-lfs installed: `git push` fails; pushes use
  `--no-verify`. Install git-lfs or delete the hooks.
