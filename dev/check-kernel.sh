#!/usr/bin/env bash
# Report whether this kernel/container can run Cantainer's sandbox features.
# Exit 0 if everything required is present, 1 otherwise.
set -uo pipefail

ok=1
echo "kernel: $(uname -r)"

# Landlock ABI version via landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION).
abi=$(python3 - <<'PY'
import ctypes, platform, os
nr = {"x86_64": 444, "aarch64": 444}.get(platform.machine())
if nr is None:
    print("unknown-arch"); raise SystemExit
libc = ctypes.CDLL(None, use_errno=True)
r = libc.syscall(nr, None, 0, 1)
print(r if r >= 0 else f"err:{os.strerror(ctypes.get_errno())}")
PY
)
case "$abi" in
  ''|err:*|unknown-arch) echo "landlock: unavailable ($abi)"; ok=0 ;;
  *)
    if [ "$abi" -ge 4 ]; then echo "landlock: ABI v$abi (network rules supported)"
    else echo "landlock: ABI v$abi (no network rules; need v4 / kernel >= 6.7)"; ok=0; fi ;;
esac

if grep -qw landlock /sys/kernel/security/lsm 2>/dev/null; then
  echo "lsm list: $(cat /sys/kernel/security/lsm)"
fi

# Unprivileged user namespaces.
if unshare --user --map-root-user true 2>/dev/null; then
  echo "user namespaces: ok"
else
  echo "user namespaces: blocked (check seccomp/apparmor or kernel.unprivileged_userns_clone)"; ok=0
fi

# seccomp filter mode.
if grep -q '^Seccomp:' /proc/self/status; then
  echo "seccomp: $(grep -E '^Seccomp(_filters)?:' /proc/self/status | tr '\n' ' ')"
fi

[ "$ok" = 1 ] && echo "OK: environment supports Cantainer sandbox tests" || echo "WARN: some sandbox features missing"
[ "$ok" = 1 ]
