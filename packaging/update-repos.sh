#!/usr/bin/env bash
# Add new packages to the APT and RPM repositories and re-sign their metadata.
#
#   SIGNING_KEY_FPR=... packaging/update-repos.sh DISTDIR REPODIR
#
# REPODIR is a checkout of github.com/cantainer/packages, served by GitHub Pages at
# https://cantainer.github.io/packages/. The script copies DISTDIR/*.deb and *.rpm into it
# (keeping older versions), regenerates the metadata and signs it with SIGNING_KEY_FPR from the
# GnuPG keyring. It doesn't commit or push.
#
# Layout:
#   signing-key.asc                       public key (packaging/signing-key.asc)
#   apt/pool/main/*.deb
#   apt/dists/stable/{Release,Release.gpg,InRelease}
#   apt/dists/stable/main/binary-{amd64,arm64}/Packages{,.gz}
#   rpm/{x86_64,aarch64}/*.rpm
#   rpm/repodata/repomd.xml{,.asc}
#   rpm/cantainer.repo                    dnf/zypper repository definition
set -euo pipefail
umask 022

dist="$(cd "${1:?usage: update-repos.sh DISTDIR REPODIR}" && pwd)"
repo="$(cd "${2:?missing REPODIR}" && pwd)"
fpr="${SIGNING_KEY_FPR:?set SIGNING_KEY_FPR to the signing key fingerprint}"
root="$(cd "$(dirname "$0")/.." && pwd)"
url="https://cantainer.github.io/packages"

gpg_sign() { gpg --batch --yes --local-user "$fpr" "$@"; }

shopt -s nullglob
debs=("$dist"/*.deb)
rpms=("$dist"/*.rpm)
[ ${#debs[@]} -gt 0 ] || { echo "update-repos: no .deb files in $dist" >&2; exit 1; }
[ ${#rpms[@]} -gt 0 ] || { echo "update-repos: no .rpm files in $dist" >&2; exit 1; }

install -m 644 "$root/packaging/signing-key.asc" "$repo/signing-key.asc"
touch "$repo/.nojekyll"   # serve files as they are; no Jekyll processing

# --- APT -------------------------------------------------------------------------------------
apt="$repo/apt"
mkdir -p "$apt/pool/main"
install -m 644 "${debs[@]}" "$apt/pool/main/"
(
  cd "$apt"
  for arch in amd64 arm64; do
    dir="dists/stable/main/binary-$arch"
    mkdir -p "$dir"
    apt-ftparchive --arch "$arch" packages pool/main > "$dir/Packages"
    gzip -9nkf "$dir/Packages"
  done
  # Old Release files must not be listed in the new one.
  rm -f dists/stable/Release dists/stable/InRelease dists/stable/Release.gpg
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin=Cantainer \
    -o APT::FTPArchive::Release::Label=Cantainer \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures="amd64 arm64" \
    -o APT::FTPArchive::Release::Components=main \
    -o APT::FTPArchive::Release::Description="Cantainer packages" \
    release dists/stable > "$repo/.Release.new"
  mv "$repo/.Release.new" dists/stable/Release
  gpg_sign --clearsign -o dists/stable/InRelease dists/stable/Release
  gpg_sign --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
)

# --- RPM -------------------------------------------------------------------------------------
rpmdir="$repo/rpm"
for f in "${rpms[@]}"; do
  arch="$(rpm -qp --qf '%{ARCH}' "$f" 2>/dev/null)"
  mkdir -p "$rpmdir/$arch"
  install -m 644 "$f" "$rpmdir/$arch/"
done
createrepo_c --quiet --update "$rpmdir"
gpg_sign --armor --detach-sign -o "$rpmdir/repodata/repomd.xml.asc" "$rpmdir/repodata/repomd.xml"
cat > "$rpmdir/cantainer.repo" <<EOF
[cantainer]
name=Cantainer
baseurl=$url/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$url/signing-key.asc
EOF

# --- Index page ------------------------------------------------------------------------------
cat > "$repo/index.html" <<EOF
<!doctype html>
<meta charset="utf-8">
<title>Cantainer packages</title>
<h1>Cantainer packages</h1>
<p>Signed APT and RPM repositories for <a href="https://github.com/cantainer/cantainer">Cantainer</a>.
Installation instructions are in the
<a href="https://github.com/cantainer/cantainer#install">README</a>.</p>
<p>Signing key: <a href="signing-key.asc">signing-key.asc</a>,
fingerprint <code>93B1 11A2 5A48 73A3 2AFA EF6D DEC0 3DB8 3F0D 540B</code>.</p>
EOF

# Pages serves files as they are, so the checkout must not keep stray modes from the sandbox.
find "$repo" -path "$repo/.git" -prune -o -type d -exec chmod 0755 {} + -o -type f -exec chmod 0644 {} +
echo "update-repos: $(ls "$apt/pool/main" | wc -l) .deb, $(find "$rpmdir" -name '*.rpm' | wc -l) .rpm"
