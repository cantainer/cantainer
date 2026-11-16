#!/usr/bin/env bash
# A local OCI registry (CNCF distribution) for testing `cant push`/`cant pull`, in the dev
# container and in CI. Pinned release, checksum checked against the values below.
#
#   dev/registry.sh install   # download the registry binary to $REGISTRY_BIN (default ~/.local/bin)
#   dev/registry.sh start     # serve on 127.0.0.1:5000 (storage in $REGISTRY_DIR), in the background
#   dev/registry.sh stop
#   dev/registry.sh status
set -euo pipefail

VERSION=3.1.2
declare -A SHA256=(
  [amd64]=40df2224d410f72ae425c3371873b078bbdbda3b8b612be9571f0e6751f3acc8
  [arm64]=09d26f88d2c0f161bd1b8bfc6c123571cc3d291dcca8af5477b3cacc4ec95e73
)
bin_dir=${REGISTRY_BIN:-$HOME/.local/bin}
state=${REGISTRY_DIR:-${TMPDIR:-/tmp}/cant-registry}
addr=${REGISTRY_ADDR:-127.0.0.1:5000}

case $(uname -m) in
x86_64) arch=amd64 ;;
aarch64) arch=arm64 ;;
*) echo "registry.sh: no pinned registry build for $(uname -m)" >&2; exit 1 ;;
esac

install() {
  if [ -x "$bin_dir/registry" ] && "$bin_dir/registry" --version 2>/dev/null | grep -q "v$VERSION"; then
    echo "registry v$VERSION already in $bin_dir"
    return
  fi
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  local tarball="registry_${VERSION}_linux_${arch}.tar.gz"
  curl -fsSL -o "$tmp/$tarball" \
    "https://github.com/distribution/distribution/releases/download/v${VERSION}/${tarball}"
  echo "${SHA256[$arch]}  $tmp/$tarball" | sha256sum -c --quiet -
  tar -xzf "$tmp/$tarball" -C "$tmp" registry
  mkdir -p "$bin_dir"
  mv "$tmp/registry" "$bin_dir/registry"
  chmod 0755 "$bin_dir/registry"
  echo "installed registry v$VERSION to $bin_dir"
}

start() {
  if status >/dev/null; then
    echo "registry already running on $addr"
    return
  fi
  mkdir -p "$state/data"
  cat >"$state/config.yml" <<YAML
version: 0.1
log:
  level: warn
storage:
  filesystem:
    rootdirectory: $state/data
  delete:
    enabled: true
http:
  addr: $addr
YAML
  "$bin_dir/registry" serve "$state/config.yml" >"$state/log" 2>&1 &
  echo $! >"$state/pid"
  for _ in $(seq 50); do
    if curl -fsS "http://$addr/v2/" >/dev/null 2>&1; then
      echo "registry running on $addr (log: $state/log)"
      return
    fi
    sleep 0.1
  done
  echo "registry.sh: registry didn't start; log:" >&2
  cat "$state/log" >&2
  exit 1
}

stop() {
  if [ -f "$state/pid" ]; then
    kill "$(cat "$state/pid")" 2>/dev/null || true
    rm -f "$state/pid"
  fi
}

status() {
  curl -fsS "http://$addr/v2/" >/dev/null 2>&1 && echo "running on $addr"
}

case ${1:-} in
install | start | stop | status) "$1" ;;
*) echo "usage: dev/registry.sh install|start|stop|status" >&2; exit 2 ;;
esac
