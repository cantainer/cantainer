#!/usr/bin/env bash
# Print the CHANGELOG.md section for one version (without its heading).
#   dev/changelog-section.sh 0.0.2      # or: Unreleased
# Exits 1 if the section is missing or empty.
set -euo pipefail
version="${1:?usage: $0 VERSION|Unreleased}"
root="$(cd "$(dirname "$0")/.." && pwd)"

section="$(awk -v v="$version" '
  /^## \[/ { if (found) exit; if (index($0, "## [" v "]") == 1) { found = 1; next } }
  found && /^\[[^]]+\]: / { exit }
  found { print }
' "$root/CHANGELOG.md" | sed -e '/./,$!d')"

if ! printf '%s\n' "$section" | grep -q '[^[:space:]]'; then
  echo "CHANGELOG.md has no entries for [$version]" >&2
  exit 1
fi
printf '%s\n' "$section"
