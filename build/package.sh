#!/bin/bash
# Build .deb and .rpm for "lguard" (core) and "lguard-gui" from build/stage/.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); repo=$(dirname "$here")
VER=$(cat "$here/stage/VERSION")
OUT=$here/out; mkdir -p "$OUT"
SCR=$repo/packaging/scripts
MAINT="Lguard Project <lodarco@users.noreply.github.com>"

# name | stage | summary | deb Depends | deb Recommends | rpm Requires | rpm Recommends
CORE_DEB_DEP="libc6 (>= 2.28), systemd"
CORE_DEB_REC="polkitd | policykit-1"
CORE_RPM_REQ="glibc >= 2.28, systemd"
CORE_RPM_REC="polkit"
GUI_DEB_DEP="lguard (= $VER), libegl1, libgl1, libxkbcommon0, libfontconfig1, libfreetype6, libdbus-1-3, libglib2.0-0"
GUI_DEB_REC="libxkbcommon-x11-0, libx11-xcb1, libxcb-cursor0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-randr0, libxcb-render-util0, libxcb-shape0, libxcb-xkb1, libwayland-client0, libwayland-cursor0, libwayland-egl1"
GUI_RPM_REQ="lguard = $VER, mesa-libEGL, mesa-libGL, libxkbcommon, fontconfig, freetype, dbus-libs, glib2"
GUI_RPM_REC="libxkbcommon-x11, libX11-xcb, xcb-util-cursor, xcb-util-wm, xcb-util-image, xcb-util-keysyms, xcb-util-renderutil, libwayland-client, libwayland-cursor, libwayland-egl"

deb() {  # name stage summary depends recommends
  local name=$1 stage=$2 summary=$3 dep=$4 rec=$5
  local D=$here/pkg-deb-$name; rm -rf "$D"; cp -a "$stage" "$D"; mkdir -p "$D/DEBIAN"
  cat > "$D/DEBIAN/control" <<EOC
Package: $name
Version: $VER
Architecture: amd64
Maintainer: $MAINT
Installed-Size: $(du -sk "$D" | cut -f1)
Depends: $dep
Recommends: $rec
Section: admin
Priority: optional
Description: $summary
 Lguard watches every file as it is written, keeps a tamper-proof inventory
 of what was scanned, checks torrent, Plex and Jellyfin downloads for fake
 movies and freezes backups when ransomware is detected. It ships its own
 scan engine and runtime and does not depend on the system's.
EOC
  if [ -d "$D/etc" ]; then ( cd "$D" && find etc -type f | sed 's#^#/#' ) > "$D/DEBIAN/conffiles"; fi
  if [ "$name" = lguard ]; then
    { echo '#!/bin/sh'; echo 'set -e'; echo '[ "$1" = configure ] || exit 0'
      echo '[ -z "$2" ] && export LGUARD_FIRST_INSTALL=1'; sed '1d' "$SCR/post-install.sh"; } > "$D/DEBIAN/postinst"
    { echo '#!/bin/sh'; echo '[ "$1" = remove ] || exit 0'; sed '1d' "$SCR/pre-remove.sh"; } > "$D/DEBIAN/prerm"
    { echo '#!/bin/sh'; echo '[ "$1" = purge ] || exit 0'; sed '1d' "$SCR/post-purge.sh"; } > "$D/DEBIAN/postrm"
  else
    printf '#!/bin/sh\ncommand -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q /usr/share/icons/hicolor || true\ncommand -v update-desktop-database >/dev/null && update-desktop-database -q || true\n' > "$D/DEBIAN/postinst"
  fi
  chmod 755 "$D"/DEBIAN/post* "$D"/DEBIAN/pre* 2>/dev/null || true
  dpkg-deb --root-owner-group --build -Zxz "$D" "$OUT/${name}_${VER}_amd64.deb" >/dev/null
  ls -l "$OUT/${name}_${VER}_amd64.deb"
}

spec() {  # name summary requires recommends files...
  local name=$1 summary=$2 req=$3 rec=$4; shift 4
  cat <<EOS
Name:           $name
Version:        $VER
Release:        1
Summary:        $summary
License:        Proprietary
URL:            https://github.com/lodarco/lguard
BuildArch:      x86_64
AutoReqProv:    no
Requires:       $req
Recommends:     $rec
%global debug_package %{nil}
%global __strip /bin/true
%global __os_install_post %{nil}
%define _build_id_links none

%description
Lguard antivirus, torrent guard and ransomware shield ($name).

%install
cp -a /stage/$name/. %{buildroot}/

%files
$(printf '%s\n' "$@")
EOS
}

deb lguard "$here/stage/core" "Antivirus, torrent guard and ransomware shield for Linux" "$CORE_DEB_DEP" "$CORE_DEB_REC"
deb lguard-gui "$here/stage/gui" "Lguard desktop app: window, side notifications, widget" "$GUI_DEB_DEP" "$GUI_DEB_REC"

R=$here/pkg-rpm; rm -rf "$R"; mkdir -p "$R" "$here/stage-rpm"
rm -rf "$here/stage-rpm"/*; cp -a "$here/stage/core" "$here/stage-rpm/lguard"; cp -a "$here/stage/gui" "$here/stage-rpm/lguard-gui"
{ spec lguard "Antivirus, torrent guard and ransomware shield for Linux" "$CORE_RPM_REQ" "$CORE_RPM_REC" \
    /opt/lguard/python /opt/lguard/clamav /opt/lguard/bin /opt/lguard/licenses /opt/lguard/MANIFEST.sha256 \
    /usr/bin/lguard '%dir /etc/lguard' '%config(noreplace) /etc/lguard/*' '/usr/lib/systemd/system/lguard*' \
    /usr/share/polkit-1/actions/io.github.lodarco.lguard.policy
  printf '\n%%post\n[ "$1" -eq 1 ] && export LGUARD_FIRST_INSTALL=1\n'; sed '1d' "$SCR/post-install.sh"
  printf '\n%%preun\nif [ "$1" -eq 0 ]; then\n'; sed '1d' "$SCR/pre-remove.sh"; printf 'fi\n'
} > "$R/lguard.spec"
spec lguard-gui "Lguard desktop app: window, side notifications, widget" "$GUI_RPM_REQ" "$GUI_RPM_REC" \
  /opt/lguard/gui /usr/bin/lguard-gui /usr/share/applications/lguard.desktop \
  '%config(noreplace) /etc/xdg/autostart/lguard.desktop' /usr/share/icons/hicolor/scalable/apps/lguard.svg \
  > "$R/lguard-gui.spec"
podman run --rm -v "$here/stage-rpm:/stage:ro,Z" -v "$R:/rpm:Z" docker.io/library/oraclelinux:8 bash -c '
  dnf -y -q install rpm-build >/dev/null &&
  for s in /rpm/*.spec; do rpmbuild -bb --define "_topdir /tmp/rb" --define "_rpmdir /rpm" "$s" >/dev/null || exit 1; done'
cp "$R"/x86_64/*.rpm "$OUT/"
ls -l "$OUT"/*-"$VER"-1.x86_64.rpm
