#!/usr/bin/env bash
# Prepare a release: bump the version, stamp the changelog, run every check, commit and tag.
#
#   dev/release.sh 0.0.2
#
# Nothing is pushed or published. To release, push the commit and the tag:
#
#   git push origin main v0.0.2
#
# The tag starts .github/workflows/release.yml, which waits for approval before publishing.
# See docs/RELEASING.md.
set -euo pipefail

new="${1:?usage: dev/release.sh X.Y.Z}"
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
repo_url="https://github.com/cantainer/cantainer"

die() { echo "release: $*" >&2; exit 1; }

[[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "'$new' is not a version (X.Y.Z)"

# --- Preconditions -------------------------------------------------------------------------
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || die "not on main"
[ -z "$(git status --porcelain)" ] || die "working tree is not clean"
git fetch --quiet origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || die "main is not in sync with origin/main"
git rev-parse -q --verify "refs/tags/v$new" >/dev/null && die "tag v$new already exists"

# CI (all targets, arm64 tests, sandbox tests) must have passed on exactly this commit.
if [ -z "${RELEASE_SKIP_CI_CHECK:-}" ]; then
  command -v gh >/dev/null || die "gh is needed to check CI (or set RELEASE_SKIP_CI_CHECK=1)"
  ci="$(gh run list --workflow ci.yml --commit "$(git rev-parse HEAD)" --limit 1 \
    --json status,conclusion --jq '.[0] | "\(.status) \(.conclusion)"' 2>/dev/null || true)"
  [ "$ci" = "completed success" ] \
    || die "CI has not passed on HEAD (${ci:-no run found}); wait for it or fix it"
fi

# The workspace version is the first `version = "..."` line, in [workspace.package].
current="$(sed -n 's/^version = "\([^"]*\)"$/\1/p' Cargo.toml | head -n1)"
[ -n "$current" ] || die "cannot find the workspace version in Cargo.toml"
[ "$new" != "$current" ] || die "version is already $current"
highest="$(printf '%s\n%s\n' "$current" "$new" | sort -V | tail -n1)"
[ "$highest" = "$new" ] || die "$new is not higher than the current version $current"

dev/changelog-section.sh Unreleased >/dev/null \
  || die "add entries under '## [Unreleased]' in CHANGELOG.md first"

echo "release: $current -> $new"

# --- Bump ------------------------------------------------------------------------------------
# Workspace version and the exact pins on the internal crates.
perl -0pi -e "s/^version = \"\Q$current\E\"\$/version = \"$new\"/m" Cargo.toml
perl -pi -e "s/version = \"=\Q$current\E\"/version = \"=$new\"/g" Cargo.toml
cargo update --workspace --quiet

# Changelog: new section under Unreleased, and comparison links.
today="$(date -u +%Y-%m-%d)"
perl -pi -e "s/^## \[Unreleased\]\$/## [Unreleased]\n\n## [$new] - $today/" CHANGELOG.md
# Compare against the version the Unreleased link starts from (the last published one).
base="$(sed -n 's|^\[Unreleased\]: .*/compare/\(v[^/]*\)\.\.\.HEAD$|\1|p' CHANGELOG.md)"
base="${base:-v$current}"
perl -pi -e "s|^\[Unreleased\]: .*\$|[Unreleased]: $repo_url/compare/v$new...HEAD\n[$new]: $repo_url/compare/$base...v$new|" CHANGELOG.md

# --- Checks ----------------------------------------------------------------------------------
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --quiet -- -D warnings
cargo test --workspace --quiet
cargo publish --dry-run --workspace --quiet --allow-dirty   # the bump is committed below

# --- Commit and tag --------------------------------------------------------------------------
git add Cargo.toml Cargo.lock CHANGELOG.md
git commit --quiet -m "Release $new"
git tag -a "v$new" -m "cantainer $new"

cat <<MSG

release: committed "Release $new" and tagged v$new. Nothing has been pushed.

  Review:   git show --stat HEAD
  Release:  git push origin main v$new
  Undo:     git tag -d v$new && git reset --hard HEAD~1
MSG
