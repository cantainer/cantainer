#!/usr/bin/env bash
# Startup overhead of `cant run cat` versus plain `cat`.
#
#   benches/startup.sh            # 1000 runs each (needs hyperfine)
#   RUNS=200 benches/startup.sh
#
# Both commands read the same small file. The difference in mean time is cant's overhead:
# parsing the manifest, resolving libraries, building Landlock and seccomp rules, and the
# extra execve.
set -euo pipefail

RUNS="${RUNS:-1000}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

command -v hyperfine >/dev/null || { echo "hyperfine is required (apt install hyperfine)"; exit 1; }

cargo build --release --quiet --manifest-path "$ROOT/Cargo.toml"
CANT="$ROOT/target/release/cant"
"$CANT" check >/dev/null || { echo "this kernel cannot sandbox cants (see: $CANT check)"; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "hello" > "$WORK/notes.txt"
cd "$WORK"

echo "kernel: $(uname -r)  cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
hyperfine --shell=none --warmup 50 --runs "$RUNS" --export-markdown "$WORK/result.md" \
  -n "cat" "cat notes.txt" \
  -n "cant run cat" "$CANT run $ROOT/examples/cat.toml notes.txt"
cat "$WORK/result.md"
