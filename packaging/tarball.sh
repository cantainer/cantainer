#!/usr/bin/env bash
# Package a built `cant` binary as a release tarball.
#
#   packaging/tarball.sh VERSION TARGET BINARY OUTDIR
#
# Writes OUTDIR/cant-vVERSION-TARGET.tar.gz with one top-level directory of the same name,
# containing the binary, the README, the changelog and both licenses. (The manifest library
# is built into the binary.)
# cargo-binstall, the Homebrew formula, the AUR package and packaging/packages.sh all rely on
# this layout.
set -euo pipefail
umask 022

version="${1:?usage: packaging/tarball.sh VERSION TARGET BINARY OUTDIR}"
target="${2:?missing TARGET}"
binary="${3:?missing BINARY}"
outdir="${4:?missing OUTDIR}"
root="$(cd "$(dirname "$0")/.." && pwd)"

name="cant-v$version-$target"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/$name" "$outdir"
install -m 755 "$binary" "$work/$name/cant"
install -m 644 "$root/README.md" "$root/CHANGELOG.md" "$root/LICENSE-MIT" "$root/LICENSE-APACHE" \
  "$work/$name/"

find "$work/$name" -type d -exec chmod 0755 {} +

# Reproducible archive: fixed order, owner and timestamps.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$SOURCE_DATE_EPOCH" \
  -C "$work" -cf - "$name" | gzip -9n > "$outdir/$name.tar.gz"
echo "$outdir/$name.tar.gz"
