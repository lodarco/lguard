#!/bin/bash
# Lguard's private Python runtime: CPython from python-build-standalone plus
# the exact, hash-pinned packages from requirements.lock, installed into
# /opt/lguard/python. Nothing from the host's Python is ever used.
#
# Mounted: /build, /cache. Output: /build/out/lguard-python-<ver>-x86_64.tar.gz
set -euo pipefail

PBS_TAG=20261026
PY_VER=3.12.16
NAME="cpython-${PY_VER}+${PBS_TAG}-x86_64-unknown-linux-gnu-install_only.tar.gz"
BASE="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}"
PREFIX=/opt/lguard/python

cd /cache
[ -s "$NAME" ] || curl -fsSL -o "$NAME" "$BASE/${NAME//+/%2B}"
curl -fsSL -o "pbs-SHA256SUMS-$PBS_TAG" "$BASE/SHA256SUMS"
grep -F " $NAME" "pbs-SHA256SUMS-$PBS_TAG" | sha256sum -c -

rm -rf "$PREFIX"; mkdir -p /opt/lguard
tar -xzf "/cache/$NAME" -C /opt/lguard      # unpacks to ./python
PY="$PREFIX/bin/python3"
"$PY" -V

"$PY" -m pip install --no-cache-dir --disable-pip-version-check --no-warn-script-location \
  --require-hashes --only-binary=:all: -r /build/python/requirements.lock

SP=$("$PY" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')

# ---- trim what Lguard never uses -----------------------------------------
cd "$PREFIX"
rm -rf share lib/tcl* lib/tk* lib/itcl* lib/thread* lib/libtcl* lib/libtk*
L=lib/python3.12
rm -rf $L/test $L/idlelib $L/tkinter $L/turtledemo $L/turtle.py $L/lib2to3 $L/ensurepip \
       $L/pydoc_data $L/config-3.12-x86_64-linux-gnu $L/lib-dynload/_tkinter*.so
find . -name '__pycache__' -type d -prune -exec rm -rf {} +

# PySide6: keep Core/Gui/Widgets/DBus/Svg/Network and the platform plugins.
cd "$SP/PySide6"
rm -rf Qt/qml Qt/libexec Qt/metatypes include typesystems glue scripts doc examples \
       assistant designer linguist lupdate lrelease qmllint qmlformat qmlls balsam* \
       Qt/translations/designer_* Qt/translations/linguist_* Qt/translations/assistant_*
for m in Qml Quick QuickControls2 QuickWidgets QuickTest Designer UiTools Pdf PdfWidgets Sql Test \
         Xml Concurrent Help OpenGLWidgets OpenGL PrintSupport; do
  rm -f Qt$m.abi3.so Qt$m.pyi Qt/lib/libQt6$m.so* 2>/dev/null || true
done
rm -f Qt/lib/libQt6Quick*.so* Qt/lib/libQt6Qml*.so* Qt/lib/libQt6Designer*.so* Qt/lib/libQt6LabsQml*.so* \
      Qt/lib/libQt6ShaderTools*.so* Qt/lib/libQt6Pdf*.so* 2>/dev/null || true
rm -rf Qt/plugins/qmltooling Qt/plugins/designer Qt/plugins/sqldrivers Qt/plugins/qmllint

# Must still import after trimming.
# (the GUI uses the desktop's own graphics libraries: GL/EGL, xkbcommon, fontconfig;
#  installed here only to prove the bundle imports, they are not shipped)
dnf -y -q install libxkbcommon mesa-libGL mesa-libEGL fontconfig freetype dbus-libs libX11 libxcb >/dev/null
QT_QPA_PLATFORM=offscreen "$PY" -I -c 'import cryptography.hazmat.primitives.ciphers.aead as a; from PySide6 import QtCore, QtGui, QtWidgets, QtDBus; app = QtWidgets.QApplication([]); print("imports ok, Qt", QtCore.qVersion())'

/build/check-glibc.sh "$PREFIX" 2.28

tar -C /opt/lguard -czf "/build/out/lguard-python-${PY_VER}-x86_64.tar.gz" python
ls -l "/build/out/lguard-python-${PY_VER}-x86_64.tar.gz"; du -sh "$PREFIX"
