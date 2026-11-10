#!/bin/bash
# Host side: run the private ClamAV build in the glibc 2.28 container.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/cache" "$here/out"
podman run --rm \
  -v "$here:/build:Z" \
  -v "$here/cache:/cache:Z" \
  quay.io/pypa/manylinux_2_28_x86_64 \
  bash /build/clamav/in-container.sh
