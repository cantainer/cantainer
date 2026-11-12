#!/usr/bin/env bash
# Publish a release's packages to the distribution channels: the signed APT and RPM
# repositories (github.com/cantainer/packages, served by Pages), the Homebrew tap and the AUR.
#
#   packaging/publish-channels.sh VERSION DISTDIR
#
# DISTDIR holds the release files: the two tarballs, .deb and .rpm packages (packages.sh).
# Environment:
#   SIGNING_KEY_FPR          signing key, already imported into GnuPG (required)
#   PACKAGES_DEPLOY_KEY      SSH deploy key for cantainer/packages (required)
#   HOMEBREW_TAP_DEPLOY_KEY  SSH deploy key for cantainer/homebrew-tap (required)
#   AUR_SSH_KEY              SSH key of the AUR account (optional: the AUR is skipped without it)
#   PACKAGES_REMOTE, HOMEBREW_TAP_REMOTE, AUR_REMOTE
#                            override the git remotes (for testing with local repositories)
#
# Every channel skips its commit when nothing changed, so running this twice is harmless.
# Used by .github/workflows/release.yml and, to re-publish an existing release, channels.yml.
set -euo pipefail
umask 022

version="${1:?usage: packaging/publish-channels.sh VERSION DISTDIR}"
dist="$(cd "${2:?missing DISTDIR}" && pwd)"
root="$(cd "$(dirname "$0")/.." && pwd)"
: "${SIGNING_KEY_FPR:?}" "${PACKAGES_DEPLOY_KEY:?}" "${HOMEBREW_TAP_DEPLOY_KEY:?}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -m 700 "$work/ssh"

# Host keys: GitHub's from https://api.github.com/meta, the AUR's from https://aur.archlinux.org/
# (SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU and SHA256:RFzBCUItH9LZS0cKB5UE6ceAYhBD5C8GeOBip8Z11+4).
cat > "$work/ssh/known_hosts" <<'EOF'
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
aur.archlinux.org ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEuBKrPzbawxA/k2g6NcyV5jmqwJ2s+zpgZGZ7tpLIcN
EOF

# git with one specific key and only the pinned host keys.
git_with_key() { # git_with_key KEYNAME GIT-ARGS...
  local key="$work/ssh/$1"
  shift
  GIT_SSH_COMMAND="ssh -i $key -o IdentitiesOnly=yes -o UserKnownHostsFile=$work/ssh/known_hosts -o StrictHostKeyChecking=yes" \
    git "$@"
}
write_key() { printf '%s\n' "$2" > "$work/ssh/$1" && chmod 600 "$work/ssh/$1"; }

# Commits everything in DIR and pushes it with KEYNAME, unless nothing changed.
commit_and_push() { # commit_and_push DIR KEYNAME MESSAGE AUTHOR EMAIL [REF]
  local dir="$1" key="$2" message="$3" name="$4" email="$5" ref="${6:-HEAD}"
  git -C "$dir" add -A
  if git -C "$dir" diff --cached --quiet; then
    echo "publish: $(basename "$dir"): no changes"
    return
  fi
  git -C "$dir" -c user.name="$name" -c user.email="$email" commit -q -m "$message"
  git_with_key "$key" -C "$dir" push -q origin "$ref"
  echo "publish: $(basename "$dir"): pushed"
}
bot_name="Cantainer release"
bot_email="41898282+github-actions[bot]@users.noreply.github.com"

# --- APT and RPM repositories -------------------------------------------------------------
write_key packages "$PACKAGES_DEPLOY_KEY"
git_with_key packages clone -q --depth 1 "${PACKAGES_REMOTE:-git@github.com:cantainer/packages.git}" "$work/packages"
"$root/packaging/update-repos.sh" "$dist" "$work/packages"
commit_and_push "$work/packages" packages "cantainer $version" "$bot_name" "$bot_email"

# --- Homebrew tap -------------------------------------------------------------------------
write_key tap "$HOMEBREW_TAP_DEPLOY_KEY"
git_with_key tap clone -q --depth 1 "${HOMEBREW_TAP_REMOTE:-git@github.com:cantainer/homebrew-tap.git}" "$work/homebrew-tap"
mkdir -p "$work/homebrew-tap/Formula"
"$root/packaging/homebrew.sh" "$version" "$dist" > "$work/homebrew-tap/Formula/cantainer.rb"
if command -v ruby >/dev/null; then ruby -c "$work/homebrew-tap/Formula/cantainer.rb" >/dev/null; fi
commit_and_push "$work/homebrew-tap" tap "cantainer $version" "$bot_name" "$bot_email"

# --- AUR ----------------------------------------------------------------------------------
if [ -z "${AUR_SSH_KEY:-}" ]; then
  echo "::notice::AUR_SSH_KEY is not set; skipping the AUR"
else
  write_key aur "$AUR_SSH_KEY"
  git_with_key aur clone -q "${AUR_REMOTE:-ssh://aur@aur.archlinux.org/cantainer-bin.git}" "$work/aur"
  # The AUR's branch is master; the clone of a new, empty package has none yet.
  git -C "$work/aur" checkout -q master 2>/dev/null || true
  "$root/packaging/aur.sh" "$version" "$dist" "$work/aur" >/dev/null
  commit_and_push "$work/aur" aur "cantainer-bin $version" "Arie Radle" "arie.radle@gmail.com" HEAD:master
fi
