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
