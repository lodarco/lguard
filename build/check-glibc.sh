#!/bin/bash
# check-glibc.sh <dir> <max-version>
# Fails if any ELF file under <dir> needs a newer glibc than <max-version>.
# This is the gate that keeps Lguard installable on every supported distro.
set -uo pipefail
dir=$1; max=$2
worst=""; bad=0
while IFS= read -r -d '' f; do
  file -b "$f" | grep -q ELF || continue
  need=$(objdump -T "$f" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' | sed 's/GLIBC_//' | sort -V | tail -1)
  [ -z "$need" ] && continue
  if [ "$(printf '%s\n%s\n' "$need" "$max" | sort -V | tail -1)" != "$max" ]; then
    echo "TOO NEW: $f needs glibc $need (max $max)"; bad=1
  fi
  if [ -z "$worst" ] || [ "$(printf '%s\n%s\n' "$need" "$worst" | sort -V | tail -1)" = "$need" ]; then worst=$need; fi
done < <(find "$dir" -type f -print0)
echo "highest glibc needed under $dir: ${worst:-none} (limit $max)"
exit $bad
