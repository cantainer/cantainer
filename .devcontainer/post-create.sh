#!/usr/bin/env bash
# One-time setup after the dev container is created.
set -euo pipefail

# Volumes are created root-owned; hand them to the dev user.
sudo chown -R "$(id -u):$(id -g)" "$HOME/.claude" /usr/local/cargo/registry 2>/dev/null || true

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential pkg-config \
  python3 \
  strace gdb file binutils \
  util-linux \
  vim curl ca-certificates \
  hyperfine \
  asciinema

# Demo GIF recorder (charmbracelet/vhs) needs ttyd + ffmpeg; install only if wanted:
#   sudo apt-get install -y ffmpeg && go install github.com/charmbracelet/vhs@latest

rustup component add rustfmt clippy rust-src
cargo --version
rustc --version
claude --version || echo "claude CLI not found on PATH yet; open a new terminal"

bash dev/check-kernel.sh || true
