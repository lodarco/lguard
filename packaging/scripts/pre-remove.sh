#!/bin/sh
# Lguard pre-remove: stop and disable services (not on upgrade).
set -e
if [ -d /run/systemd/system ]; then
  systemctl disable --now lguardd.service lguard-sweep.timer lguard-freshclam.timer lguard-clamd.service >/dev/null 2>&1 || true
fi
exit 0
