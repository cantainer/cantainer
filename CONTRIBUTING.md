# Contributing

Thanks for helping. Cantainer is security software, so correctness and clear errors beat
cleverness. Boring, explicit code is welcome.

## Setup

Cantainer runs on Linux (kernel ≥ 6.2, ideally ≥ 6.7). On macOS the workspace compiles, but
nothing can be sandboxed. Use one of these:

- **Dev container:** open the repository in VS Code with the Dev Containers extension (or in
  GitHub Codespaces). The container runs without Docker's own seccomp profile so that `cant`
  can install its own.
- **Lima VM (macOS):** see the README quickstart and [`dev/lima.yaml`](dev/lima.yaml).

Then:

```sh
cargo run -p cantainer -- check    # can this kernel sandbox cants?
cargo test --workspace             # unit + integration tests
```

## Before you open a pull request

```sh
cargo fmt --all
dev/check.sh        # fmt check, clippy for every supported target, tests: what CI runs
```

`dev/check.sh` checks x86_64 and aarch64 (glibc and musl) and riscv64; it says which targets it
skipped because their standard library isn't installed. CI runs the same checks, the sandbox
tests on x86_64 and natively on arm64, and a macOS build.

## Rules of the road

- `#![forbid(unsafe_code)]` in every crate. If you need a syscall nobody wraps safely, propose a
  small, documented shim in an issue first.
- Verify crate names, versions and APIs on crates.io and docs.rs. Don't add dependencies from
  memory.
- New capabilities or relaxed checks need a test that shows the sandbox still denies what it
  should, and an entry in `docs/ARCHITECTURE.md` explaining the decision and the alternatives.
- When a kernel or library limitation forces a design change, say so in the PR. Don't work around
  it quietly.
- Error messages are part of the interface. Keep the voice: `cant: vim can't write ~/.ssh/config (…)`.
- Keep commits small and logical, with clear messages.
- Add a line to `CHANGELOG.md` under `## [Unreleased]` for anything users notice: features,
  fixes, behaviour changes, and anything security-relevant (under **Security**). Releases are
  described in [docs/RELEASING.md](docs/RELEASING.md).

## License

By contributing you agree that your contributions are licensed under both the MIT and Apache-2.0
licenses, as the rest of the project is.
