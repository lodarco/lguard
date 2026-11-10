#!/bin/bash
# test-install.sh <image>...   Install the built package into a clean container
# of each distro and prove it works: postinst, key, manifest, own clamd with the
# shared signature DB, EICAR caught and quarantined, inventory verify.
# test-install.sh --fetch-db   download signatures once (with Lguard's own freshclam)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
VER=$(cat "$here/stage/VERSION")
DB=$here/cache/clamdb; mkdir -p "$DB"

inner_common='
set -e
mkdir -p /run/lguard-clamd && chown lguard-clamav:lguard /run/lguard-clamd && chmod 750 /run/lguard-clamd
cp /db/*.c?d /db/*.sign /var/lib/lguard/clamav/ && chown lguard-clamav:lguard /var/lib/lguard/clamav/*
runuser -u lguard-clamav -- /opt/lguard/clamav/sbin/clamd --config-file=/etc/lguard/clamd.conf --foreground=false
for i in $(seq 1 90); do [ -S /run/lguard-clamd/clamd.sock ] && break; sleep 2; done
printf "X5O!P%%@AP[4\\\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*" > /root/eicar.com
mkdir -p /srv/torrents/Film && printf "MZ\x90\x00junk" > /srv/torrents/Film/Codec.exe
echo "categories = { torrents = [\"/srv/torrents\"] }" >> /etc/lguard/lguard.toml
lguard scan /root/eicar.com /srv/torrents /etc/hostname || true
echo "--- status"; lguard status
echo "--- verify"; lguard verify
echo "--- quarantine"; lguard quarantine list
test ! -e /root/eicar.com && test ! -e /srv/torrents/Film/Codec.exe && echo "RESULT: OK"
'

if [ "${1:-}" = "--fetch-db" ]; then
  podman run --rm -v "$here/out:/out:ro,Z" -v "$DB:/var/lib/lguard/clamav:Z" docker.io/library/oraclelinux:8 bash -c "
    dnf -y -q install /out/lguard-$VER-1.x86_64.rpm >/dev/null 2>&1; chmod 711 /var/lib/lguard
    chown -R lguard-clamav:lguard /var/lib/lguard/clamav
    /opt/lguard/bin/lguard-freshclam --stdout --foreground 2>&1 | tail -5
    chown -R $(id -u):$(id -g) /var/lib/lguard/clamav"
  ls -l "$DB"; exit 0
fi

for img in "$@"; do
  echo "################ $img"
  case "$img" in
    *debian*|*ubuntu*)
      prep='export DEBIAN_FRONTEND=noninteractive
            if grep -qs "buster" /etc/os-release; then
              printf "deb http://archive.debian.org/debian buster main\ndeb http://archive.debian.org/debian-security buster/updates main\n" > /etc/apt/sources.list; fi
            apt-get -qq update >/dev/null && apt-get -qq install -y /out/lguard_'"$VER"'_amd64.deb >/tmp/inst.log 2>&1 || { tail -20 /tmp/inst.log; exit 1; }
            grep -iE "lguard|manifest" /tmp/inst.log | tail -5' ;;
    *)
      prep='dnf -y -q install /out/lguard-'"$VER"'-1.x86_64.rpm >/tmp/inst.log 2>&1 || { tail -20 /tmp/inst.log; exit 1; }
            grep -iE "lguard|manifest" /tmp/inst.log | tail -5' ;;
  esac
  podman run --rm -v "$here/out:/out:ro,Z" -v "$DB:/db:ro,Z" "$img" bash -c "
    $prep
    echo \"glibc: \$(ldd --version | head -1)\"
    echo \"key: \$(ls /var/lib/lguard/ | tr '\n' ' ')\"
    $inner_common" 2>&1 | tail -40
done
