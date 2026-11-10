#!/bin/bash
# Assemble the installable tree (build/stage/) from the built runtimes and the
# app source. Two payloads:
#   stage/core  -> package "lguard"     : /opt/lguard/{python,clamav,bin}, units, config
#   stage/gui   -> package "lguard-gui" : /opt/lguard/gui (Qt), desktop entry
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd); repo=$(dirname "$here")
VER=$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$repo/src/lguard/__init__.py")
CLAM_TGZ=$(ls "$here"/out/lguard-clamav-*-x86_64.tar.gz | tail -1)
PY_TGZ=$(ls "$here"/out/lguard-python-*-x86_64.tar.gz | tail -1)

S=$here/stage; rm -rf "$S"; mkdir -p "$S/core/opt/lguard" "$S/gui/opt/lguard/gui"
C=$S/core
tar -xzf "$CLAM_TGZ" -C "$C/opt/lguard"
tar -xzf "$PY_TGZ" -C "$C/opt/lguard"
SP=$(ls -d "$C"/opt/lguard/python/lib/python3.*/site-packages)

# Qt goes to the GUI package only
mkdir -p "$S/gui/opt/lguard/gui/site-packages"
for m in PySide6 shiboken6 PySide6_Essentials-*.dist-info shiboken6-*.dist-info; do
  for p in "$SP"/$m; do [ -e "$p" ] && mv "$p" "$S/gui/opt/lguard/gui/site-packages/"; done
done

# the app itself, byte-compiled with the bundled interpreter
rsync -a --delete --exclude __pycache__ "$repo/src/lguard/" "$SP/lguard/"
podman run --rm -v "$C/opt/lguard:/opt/lguard:Z" quay.io/pypa/manylinux_2_28_x86_64 \
  /opt/lguard/python/bin/python3 -I -m compileall -q /opt/lguard/python/lib >/dev/null

install -d "$C/opt/lguard/bin" "$C/usr/bin" "$C/etc/lguard" "$C/usr/lib/systemd/system" \
           "$C/opt/lguard/licenses"
install -m 755 "$repo"/packaging/bin/* "$C/opt/lguard/bin/"
ln -sf /opt/lguard/bin/lguard "$C/usr/bin/lguard"
install -m 644 "$repo"/packaging/etc/* "$C/etc/lguard/"
install -m 644 "$repo"/packaging/systemd/* "$C/usr/lib/systemd/system/"

install -D -m 644 "$repo/packaging/polkit/io.github.lodarco.lguard.policy" \
  "$C/usr/share/polkit-1/actions/io.github.lodarco.lguard.policy"

# ---- GUI payload
G=$S/gui
install -D -m 755 "$repo/packaging/gui/lguard-gui" "$G/opt/lguard/gui/bin/lguard-gui"
install -d "$G/usr/bin"; ln -sf /opt/lguard/gui/bin/lguard-gui "$G/usr/bin/lguard-gui"
install -D -m 644 "$repo/packaging/gui/lguard.desktop" "$G/usr/share/applications/lguard.desktop"
install -D -m 644 "$repo/packaging/gui/lguard-autostart.desktop" "$G/etc/xdg/autostart/lguard.desktop"
install -D -m 644 "$repo/packaging/gui/lguard.svg" "$G/usr/share/icons/hicolor/scalable/apps/lguard.svg"
install -d "$G/opt/lguard/gui/licenses"
install -m 644 "$repo"/packaging/licenses/* "$G/opt/lguard/gui/licenses/"

# licences of everything bundled + where the sources are
cat > "$C/opt/lguard/licenses/BUNDLED.txt" <<EOF
Lguard $VER bundles these third-party components, unmodified, each under its own licence:
$(grep -v '^#' "$here/clamav/sources.txt" | awk '{printf "  %-9s %-8s %s\n", $1, $2, $3}')
  python   $(basename "$PY_TGZ" | sed 's/lguard-python-//; s/-x86_64.tar.gz//')  python-build-standalone (PSF licence)
$(grep -E '^[A-Za-z].*==' "$here/python/requirements.lock" | sed 's/ \\$//; s/^/  /')
ClamAV is GPL-2.0: its complete source is the clamav tarball listed above
(SHA-256 in SHA256-SOURCES.txt); a copy is available from the Lguard
project on request for three years from this release.
EOF
cp "$here/clamav/SHA256SUMS" "$C/opt/lguard/licenses/SHA256-SOURCES.txt"
install -m 644 "$repo/LICENSE" "$C/opt/lguard/licenses/LGUARD-LICENSE.txt"
install -D -m 644 /dev/stdin "$C/usr/share/doc/lguard/copyright" <<COPY
Lguard - antivirus, download guard and ransomware shield for Linux
Copyright (C) 2026 lodarco
https://github.com/lodarco/lguard

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License version 3 as published by
the Free Software Foundation. Full text: /opt/lguard/licenses/LGUARD-LICENSE.txt

Bundled third-party components and their licences: /opt/lguard/licenses
COPY

# manifest: SHA-256 of every shipped file under /opt/lguard (self-check)
( cd "$C" && find opt/lguard -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum ) \
  > "$C/opt/lguard/MANIFEST.sha256"
( cd "$S/gui" && find opt/lguard/gui -type f -print0 | sort -z | xargs -0 sha256sum ) \
  > "$S/gui/opt/lguard/gui/MANIFEST.sha256"

"$here/check-glibc.sh" "$C/opt/lguard" 2.28
"$here/check-glibc.sh" "$S/gui/opt/lguard/gui" 2.28
du -sh "$C/opt/lguard" "$S/gui/opt/lguard/gui"
echo "$VER" > "$S/VERSION"
