# Development environments

Cantainer needs Linux to run (Landlock and seccomp). Two supported setups:

- **Dev container** (`.devcontainer/`): VS Code Dev Containers or GitHub Codespaces. Containers
  share the host kernel, so the host needs Linux ≥ 6.2 (≥ 6.7 for Landlock network rules). On
  macOS, Docker runs a Linux VM. OrbStack, Docker Desktop and Lima all use recent kernels; check
  with `dev/check-kernel.sh` inside the container.
- **Lima VM** (`lima.yaml`): a plain Ubuntu 24.04 VM (Linux 6.8) on macOS. See the README
  quickstart.

`check-kernel.sh` reports whether the running kernel has what the sandbox needs. Once the code
builds, `cargo run -p cantainer -- check` is the authoritative check.

## Local OCI registry

`dev/registry.sh install|start|stop|status` runs the CNCF `distribution` registry (pinned
release, checksum-verified) on `127.0.0.1:5000`. The dev container installs it and starts it on
every start, and sets `CANT_TEST_REGISTRY=127.0.0.1:5000`, which enables the push/pull
integration test (`a_can_goes_through_a_registry`). CI does the same in the `sandbox` and
`arm64` jobs.
