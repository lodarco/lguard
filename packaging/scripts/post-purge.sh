#!/bin/sh
# Lguard purge: remove the inventory, key, signatures and logs.
# Quarantined files are kept (they may be evidence), unless empty.
set -e
rm -rf /var/lib/lguard/clamav /var/log/lguard
rm -f /var/lib/lguard/index.db* /var/lib/lguard/master.cred /var/lib/lguard/master.key /var/lib/lguard/anchor.cred
rmdir /var/lib/lguard/quarantine /var/lib/lguard 2>/dev/null || \
  echo "lguard: /var/lib/lguard/quarantine kept (not empty)"
getent passwd lguard-clamav >/dev/null && userdel lguard-clamav || true
getent group lguard >/dev/null && groupdel lguard || true
exit 0
