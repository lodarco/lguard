#!/bin/bash
# Builds Lguard's private ClamAV and every library it needs into
# /opt/lguard/clamav, inside the manylinux_2_28 container (glibc 2.28), so the
# result runs on any distribution with glibc >= 2.28 and never touches or
# depends on the system's own ClamAV, OpenSSL, curl, libxml2 ...
#
# Mounted: /build (this repo's build/), /cache (source tarballs + rust).
# Output:  /build/out/lguard-clamav-<ver>-x86_64.tar.gz
set -euo pipefail

PREFIX=/opt/lguard/clamav
JOBS=$(nproc)
W=/tmp/work
mkdir -p "$W" /build/out

log() { printf '\n=== %s\n' "$*"; }

log "build tools"
dnf -y -q install perl-IPC-Cmd perl-Pod-Html perl-Time-Piece file binutils ncurses-devel >/dev/null

# ---------------------------------------------------------------- sources
log "verifying source tarballs"
cd /cache
sha256sum -c /build/clamav/SHA256SUMS

ver() { awk -v n="$1" '$1==n {print $2}' /build/clamav/sources.txt; }
unpack() {  # name -> directory
  local f; f=$(awk -v n="$1" '$1==n {print $3}' /build/clamav/sources.txt); f=$(basename "$f")
  rm -rf "$W/$1"; mkdir -p "$W/$1"
  tar --no-same-owner -xf "/cache/$f" -C "$W/$1" --strip-components=1
  echo "$W/$1"
}

export CFLAGS="-O2 -fPIC" CXXFLAGS="-O2 -fPIC"
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"
CM=(-DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib
    -DCMAKE_PREFIX_PATH="$PREFIX" -DBUILD_SHARED_LIBS=ON -DBUILD_TESTING=OFF)

# ---------------------------------------------------------------- rust
log "rust toolchain"
export RUSTUP_HOME=/cache/rust/rustup CARGO_HOME=/cache/rust/cargo
export PATH="$CARGO_HOME/bin:$PATH"
RUST_TOOLCHAIN=1.90.0
if ! command -v rustup >/dev/null; then
  mkdir -p /cache/rust
  curl -fsSL -o /tmp/rustup-init https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
  want=$(curl -fsSL https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init.sha256 | awk '{print $1}')
  echo "$want  /tmp/rustup-init" | sha256sum -c -
  chmod +x /tmp/rustup-init
  /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain "$RUST_TOOLCHAIN"
fi
rustup toolchain install --profile minimal "$RUST_TOOLCHAIN" >/dev/null 2>&1; rustup default "$RUST_TOOLCHAIN" >/dev/null
cargo --version

# ---------------------------------------------------------------- deps
log "zlib $(ver zlib)"
d=$(unpack zlib); cd "$d"
./configure --prefix="$PREFIX" >/dev/null && make -j"$JOBS" >/dev/null && make install >/dev/null

log "bzip2 $(ver bzip2)"
d=$(unpack bzip2); cd "$d"
make -f Makefile-libbz2_so CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64" >/dev/null
install -m 644 bzlib.h "$PREFIX/include/"
install -m 755 libbz2.so.1.0.8 "$PREFIX/lib/"
ln -sf libbz2.so.1.0.8 "$PREFIX/lib/libbz2.so.1.0"; ln -sf libbz2.so.1.0 "$PREFIX/lib/libbz2.so"

log "openssl $(ver openssl)"
d=$(unpack openssl); cd "$d"
./Configure linux-x86_64 --prefix="$PREFIX" --libdir=lib --openssldir="$PREFIX/ssl" \
  shared no-tests no-docs no-apps >/dev/null
make -j"$JOBS" >/dev/null && make install_sw >/dev/null

log "libxml2 $(ver libxml2)"
d=$(unpack libxml2); cd "$d"
cmake -S . -B b "${CM[@]}" -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_LZMA=OFF -DLIBXML2_WITH_ICU=OFF \
  -DLIBXML2_WITH_ZLIB=ON -DLIBXML2_WITH_TESTS=OFF -DLIBXML2_WITH_PROGRAMS=OFF >/dev/null
cmake --build b -j"$JOBS" >/dev/null && cmake --install b >/dev/null

log "pcre2 $(ver pcre2)"
d=$(unpack pcre2); cd "$d"
cmake -S . -B b "${CM[@]}" -DPCRE2_BUILD_PCRE2GREP=OFF -DPCRE2_BUILD_TESTS=OFF -DPCRE2_SUPPORT_JIT=ON >/dev/null
cmake --build b -j"$JOBS" >/dev/null && cmake --install b >/dev/null

log "json-c $(ver json-c)"
d=$(unpack json-c); cd "$d"
cmake -S . -B b "${CM[@]}" -DBUILD_STATIC_LIBS=OFF -DDISABLE_WERROR=ON >/dev/null
cmake --build b -j"$JOBS" >/dev/null && cmake --install b >/dev/null

log "curl $(ver curl)"
d=$(unpack curl); cd "$d"
# CA certificates come from the host at run time (SSL_CERT_FILE, set by
# lguard-freshclam), so no distribution's path is baked in.
cmake -S . -B b "${CM[@]}" -DCURL_USE_OPENSSL=ON -DOPENSSL_ROOT_DIR="$PREFIX" \
  -DCURL_CA_FALLBACK=ON -DCURL_CA_BUNDLE=none -DCURL_CA_PATH=none \
  -DUSE_LIBIDN2=OFF -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF \
  -DUSE_NGHTTP2=OFF -DCURL_DISABLE_LDAP=ON -DBUILD_CURL_EXE=OFF -DENABLE_CURL_MANUAL=OFF \
  -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DBUILD_EXAMPLES=OFF >/dev/null
cmake --build b -j"$JOBS" >/dev/null && cmake --install b >/dev/null

# ---------------------------------------------------------------- clamav
log "clamav $(ver clamav)"
d=$(unpack clamav); cd "$d"
cmake -S . -B b "${CM[@]}" -DOPENSSL_ROOT_DIR="$PREFIX" \
  -DAPP_CONFIG_DIRECTORY="$PREFIX/etc" -DDATABASE_DIRECTORY=/var/lib/lguard/clamav \
  -DENABLE_TESTS=OFF -DENABLE_MILTER=OFF -DENABLE_CLAMONACC=OFF -DENABLE_SYSTEMD=OFF \
  -DENABLE_JSON_SHARED=ON -DENABLE_EXTERNAL_MSPACK=OFF -DENABLE_MAN_PAGES=OFF \
  -DENABLE_DOXYGEN=OFF -DENABLE_EXAMPLES=OFF -DENABLE_UNRAR=ON >/dev/null
cmake --build b -j"$JOBS" 2>&1 | grep -E 'error|warning: unused' | head -20 || true
cmake --build b -j"$JOBS" >/dev/null
cmake --install b >/dev/null
# APP_CONFIG_DIRECTORY is inside the prefix so the compiled-in CVD certificate
# path (etc/certs, used e.g. by freshclam's database test load) is ours.
test -s "$PREFIX/etc/certs/clamav.crt"

# ---------------------------------------------------------------- tidy
log "trim, set rpath"
cd "$PREFIX"
rm -rf include share lib/pkgconfig lib/cmake ssl/misc
rm -f etc/*.sample
find . -name '*.a' -delete -o -name '*.la' -delete
rm -f bin/curl-config bin/xml2-config bin/pcre2-config bin/clamav-config bin/c_rehash bin/clamdtop 2>/dev/null || true
for f in $(find bin sbin lib -type f 2>/dev/null); do
  file -b "$f" | grep -q ELF || continue
  case "$f" in
    lib/*) patchelf --set-rpath '$ORIGIN' "$f" ;;
    *)     patchelf --set-rpath '$ORIGIN/../lib' "$f" ;;
  esac
done

log "glibc check"
/build/check-glibc.sh "$PREFIX" 2.28

v=$(ver clamav)
tar -C /opt/lguard -czf "/build/out/lguard-clamav-$v-x86_64.tar.gz" clamav
ls -l "/build/out/lguard-clamav-$v-x86_64.tar.gz"
du -sh "$PREFIX"
"$PREFIX/bin/clamscan" --version
