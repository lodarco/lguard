#!/bin/sh
# Lguard post-install (shared by .deb postinst and .rpm %post). Idempotent.
set -e
getent group lguard >/dev/null || groupadd -r lguard
getent passwd lguard-clamav >/dev/null || \
  useradd -r -g lguard -d /var/lib/lguard/clamav -s /sbin/nologin -c "Lguard scan engine" lguard-clamav
# 0711: the scan engine may pass through to its own clamav/ subfolder, but
# cannot list or read anything here (index.db, keys and quarantine are 0600/0700)
install -d -m 0711 -o root -g root /var/lib/lguard
install -d -m 0700 -o root -g root /var/lib/lguard/quarantine
install -d -m 0755 -o lguard-clamav -g lguard /var/lib/lguard/clamav
install -d -m 0750 -o lguard-clamav -g lguard /var/log/lguard

# Self-check of what was just installed (manifest shipped in the package).
if ! (cd / && sha256sum --quiet -c /opt/lguard/MANIFEST.sha256); then
  echo "lguard: installed files do not match the package manifest" >&2
fi

# The inventory key: created once, sealed to this machine (TPM 2.0 if present).
if [ ! -e /var/lib/lguard/master.cred ] && [ ! -e /var/lib/lguard/master.key ]; then
  /opt/lguard/bin/lguard init || echo "lguard: could not create the inventory key, run 'lguard init'" >&2
fi

if [ -d /run/systemd/system ]; then
  systemctl daemon-reload
  systemctl enable lguard-freshclam.timer lguard-clamd.service lguardd.service lguard-sweep.timer >/dev/null 2>&1 || true
  # first signatures, then the engine, then protection; the first full scan
  # starts in the background and reads every file once.
  systemctl start lguard-freshclam.service || true
  systemctl restart lguard-clamd.service || true
  systemctl restart lguardd.service || true
  systemctl start lguard-freshclam.timer lguard-sweep.timer || true
  if [ "${LGUARD_FIRST_INSTALL:-0}" = 1 ]; then
    systemctl start --no-block lguard-sweep.service || true
  fi
fi
exit 0
