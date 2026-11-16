#!/usr/bin/env bash
# Run what CI runs, before pushing: fmt, clippy for every supported target, tests.
#
#   dev/check.sh
#
# Targets whose standard library isn't installed are skipped with a note; add them with
#   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-gnu \
#     aarch64-unknown-linux-musl riscv64gc-unknown-linux-gnu
#
# The TLS crypto of the registry client (ring) contains C and assembly, so every target needs a
# C compiler for it (the dev container installs these; see docs/ARCHITECTURE.md):
#   sudo apt-get install clang llvm musl-tools gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
#     gcc-riscv64-linux-gnu libc6-dev-riscv64-cross
set -euo pipefail
cd "$(dirname "$0")/.."

# aarch64 musl has no packaged cross compiler; clang targets it from other hosts (ring needs no
# libc headers). On an aarch64 host, musl-gcc is the native compiler.
if [ "$(uname -m)" != aarch64 ]; then
  export CC_aarch64_unknown_linux_musl=${CC_aarch64_unknown_linux_musl:-clang}
  export AR_aarch64_unknown_linux_musl=${AR_aarch64_unknown_linux_musl:-llvm-ar}
fi

targets=(
  x86_64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-gnu
  aarch64-unknown-linux-musl
  riscv64gc-unknown-linux-gnu
)

cargo fmt --all -- --check
installed="$(rustup target list --installed 2>/dev/null || true)"
skipped=()
for t in "${targets[@]}"; do
  if grep -qx "$t" <<<"$installed"; then
    echo "check: clippy $t"
    cargo clippy --quiet --workspace --all-targets --locked --target "$t" -- -D warnings
  else
    skipped+=("$t")
  fi
done
cargo test --quiet --workspace --locked
if [ ${#skipped[@]} -gt 0 ]; then
  echo "check: passed, but NOT checked for: ${skipped[*]} (rustup target add ...)" >&2
else
  echo "check: passed for all targets"
fi
