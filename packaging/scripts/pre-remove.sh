#!/bin/sh
# Lguard pre-remove: stop and disable services (not on upgrade).
set -e
if [ -d /run/systemd/system ]; then
  systemctl stop lguard-sweep.service lguard-fullscan.service >/dev/null 2>&1 || true
  systemctl disable --now lguardd.service lguard-sweep.timer lguard-freshclam.timer lguard-clamd.service >/dev/null 2>&1 || true
fi
exit 0
