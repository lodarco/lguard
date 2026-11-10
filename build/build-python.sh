#!/bin/bash
# Host side: build Lguard's private Python runtime in the glibc 2.28 container.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/cache" "$here/out"
podman run --rm -v "$here:/build:Z" -v "$here/cache:/cache:Z" \
  quay.io/pypa/manylinux_2_28_x86_64 \
  bash -c 'dnf -y -q install file binutils >/dev/null; bash /build/python/in-container.sh'
