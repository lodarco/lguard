#!/bin/bash
# Download the pinned third-party sources (build/clamav/sources.txt) into
# build/cache and refuse anything whose SHA-256 is not in SHA256SUMS.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/cache"
cd "$here/cache"
grep -v '^#' "$here/clamav/sources.txt" | while read -r name ver url; do
  [ -n "$name" ] || continue
  f=$(basename "$url")
  [ -s "$f" ] || curl -fsSL --retry 3 -o "$f" "$url"
done
sha256sum -c "$here/clamav/SHA256SUMS"
