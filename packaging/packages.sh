#!/usr/bin/env bash
# Build .deb and .rpm packages from the release tarballs.
#
#   packaging/packages.sh VERSION DISTDIR
#
# Reads DISTDIR/cant-vVERSION-{x86_64,aarch64}-unknown-linux-musl.tar.gz (from tarball.sh)
# and writes cantainer_VERSION-1_{amd64,arm64}.deb and cantainer-VERSION-1.{x86_64,aarch64}.rpm
# next to them. Uses only dpkg-deb and rpmbuild, so no packaging tool is downloaded.
#
# When SIGNING_KEY_FPR is set, the .rpm files are signed with that key from the GnuPG keyring.
# (APT signs the repository metadata, not the .deb files; see update-repos.sh.)
set -euo pipefail
umask 022

version="${1:?usage: packaging/packages.sh VERSION DISTDIR}"
dist="$(cd "${2:?missing DISTDIR}" && pwd)"
root="$(cd "$(dirname "$0")/.." && pwd)"

# Package managers sort pre-releases before the release only with `~` (1.0.0~rc.1 < 1.0.0).
pkgversion="${version//-/\~}"
release=1
maintainer="Arie Radle <arie.radle@gmail.com>"
summary="Run every executable as a least-privilege capsule"
homepage="https://github.com/cantainer/cantainer"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Stage the file tree a package installs: binary, docs, licenses.
stage() { # stage SRC DEST ZSHDIR (Debian and Fedora look for zsh completions in different places)
  local src="$1" dest="$2" zshdir="$3"
  install -Dm755 "$src/cant" "$dest/usr/bin/cant"
  install -Dm644 "$src/completions/cant.bash" "$dest/usr/share/bash-completion/completions/cant"
  install -Dm644 "$src/completions/_cant" "$dest$zshdir/_cant"
  install -Dm644 "$src/completions/cant.fish" "$dest/usr/share/fish/vendor_completions.d/cant.fish"
  install -Dm644 -t "$dest/usr/share/man/man1" "$src"/man/*.1.gz
  install -dm755 "$dest/etc/cantainer/cants"
  install -Dm644 -t "$dest/usr/share/doc/cantainer" "$src/README.md" "$src/CHANGELOG.md"
  install -Dm644 -t "$dest/usr/share/licenses/cantainer" "$src/LICENSE-MIT" "$src/LICENSE-APACHE"
}

build_deb() { # build_deb SRC DEBARCH
  local src="$1" arch="$2" pkg="$work/deb-$2"
  stage "$src" "$pkg" /usr/share/zsh/vendor-completions
  # Debian policy wants the license text in /usr/share/doc/PACKAGE/copyright.
  {
    echo "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/"
    echo "Upstream-Name: cantainer"
    echo "Source: $homepage"
    echo
    echo "Files: *"
    echo "Copyright: The Cantainer authors"
    echo "License: MIT or Apache-2.0"
    echo
    echo "License: MIT"
    sed 's/^$/./; s/^/ /' "$src/LICENSE-MIT"
    echo
    echo "License: Apache-2.0"
    echo " On Debian systems, the full text is in /usr/share/common-licenses/Apache-2.0."
  } > "$pkg/usr/share/doc/cantainer/copyright"
  chmod 0644 "$pkg/usr/share/doc/cantainer/copyright"
  local size
  size="$(du -sk --exclude=DEBIAN "$pkg" | cut -f1)"
  mkdir -p "$pkg/DEBIAN"
  find "$pkg" -type d -exec chmod 0755 {} +
  cat > "$pkg/DEBIAN/control" <<EOF
Package: cantainer
Version: $pkgversion-$release
Architecture: $arch
Maintainer: $maintainer
Installed-Size: $size
Section: utils
Priority: optional
Homepage: $homepage
Description: $summary
 Cantainer runs a program as a "cant": it can touch only what its manifest
 declares and the files named on its command line. The kernel enforces this
 with Landlock and seccomp. No daemon, no root. Installs the \`cant\` command.
EOF
  find "$pkg" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  dpkg-deb --root-owner-group -Zxz --build "$pkg" "$dist/cantainer_${pkgversion}-${release}_${arch}.deb" >/dev/null
}

build_rpm() { # build_rpm SRC RPMARCH
  local src="$1" arch="$2" top="$work/rpm-$2"
  mkdir -p "$top"/{SPECS,RPMS,BUILD,BUILDROOT}
  cat > "$top/SPECS/cantainer.spec" <<EOF
Name:           cantainer
Version:        $pkgversion
Release:        $release
Summary:        $summary
License:        MIT OR Apache-2.0
URL:            $homepage
# A static binary: no library dependencies, nothing to strip or split out.
AutoReqProv:    no
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

%description
Cantainer runs a program as a "cant": it can touch only what its manifest
declares and the files named on its command line. The kernel enforces this
with Landlock and seccomp. No daemon, no root. Installs the \`cant\` command.

%install
mkdir -p %{buildroot}
cp -a $top/stage/. %{buildroot}/

%files
/usr/bin/cant
%dir /etc/cantainer
%dir /etc/cantainer/cants
/usr/share/bash-completion/completions/cant
/usr/share/zsh/site-functions/_cant
/usr/share/fish/vendor_completions.d/cant.fish
/usr/share/man/man1/cant*.1.gz
%doc /usr/share/doc/cantainer
%license /usr/share/licenses/cantainer
EOF
  stage "$src" "$top/stage" /usr/share/zsh/site-functions
  find "$top/stage" -type d -exec chmod 0755 {} +
  rpmbuild --quiet -bb --target "$arch-linux" \
    --define "_topdir $top" \
    --define "_buildhost reproducible" \
    --define "use_source_date_epoch_as_buildtime 1" \
    --define "clamp_mtime_to_source_date_epoch 1" \
    "$top/SPECS/cantainer.spec"
  cp "$top/RPMS/$arch/cantainer-$pkgversion-$release.$arch.rpm" "$dist/"
}

for arch in x86_64 aarch64; do
  case "$arch" in x86_64) debarch=amd64 ;; aarch64) debarch=arm64 ;; esac
  name="cant-v$version-$arch-unknown-linux-musl"
  tar -xzf "$dist/$name.tar.gz" -C "$work"
  build_deb "$work/$name" "$debarch"
  build_rpm "$work/$name" "$arch"
done

if [ -n "${SIGNING_KEY_FPR:-}" ]; then
  rpmsign --addsign --define "_gpg_name $SIGNING_KEY_FPR" "$dist"/cantainer-"$pkgversion"-"$release".*.rpm >/dev/null
fi

ls -1 "$dist"/cantainer[_-]"$pkgversion"*
