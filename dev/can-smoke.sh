#!/usr/bin/env bash
# Cross-distribution check for cans (CI jobs `cans-*`). A can carries its own libc and ELF
# loader, so a can packed on one distribution must run on another.
#
#   dev/can-smoke.sh pack DIR   # pack the built-in cat and git cants into DIR
#   dev/can-smoke.sh run DIR    # run the cans in DIR here
#
# Uses `cant` from PATH, or $CANT.
set -euo pipefail

cant=${CANT:-cant}
cmd=${1:?usage: can-smoke.sh pack|run DIR}
mkdir -p "${2:?usage: can-smoke.sh pack|run DIR}"
dir=$(cd "$2" && pwd)
. /etc/os-release
here=$PRETTY_NAME

fail() {
  echo "can-smoke: $*" >&2
  exit 1
}

case $cmd in
pack)
  for c in cat git; do
    rm -rf "$dir/$c.can"
    "$cant" pack "$c" -o "$dir/$c.can"
  done
  echo "$here" >"$dir/packed-on"
  ;;
run)
  packed_on=$(cat "$dir/packed-on")
  echo "cans packed on: $packed_on"
  echo "running on:     $here"
  "$cant" check
  work=$(mktemp -d)
  cd "$work"
  echo hello >notes.txt
  out=$("$cant" run "$dir/cat.can" notes.txt) || fail "cat.can failed"
  [ "$out" = hello ] || fail "cat.can printed '$out'"
  # The can must not use the host's libraries: none may be granted.
  if "$cant" run --explain "$dir/cat.can" notes.txt | grep -E ' library$'; then
    fail "host libraries were granted to cat.can"
  fi
  mkdir repo
  cd repo
  git init -q
  echo x >a.txt
  out=$("$cant" run "$dir/git.can" status --short) || fail "git.can failed"
  [ "$out" = "?? a.txt" ] || fail "git.can status printed '$out'"
  "$cant" run "$dir/git.can" --version
  echo "can-smoke: cans packed on $packed_on run on $here"
  ;;
*)
  fail "unknown command $cmd"
  ;;
esac
