#!/usr/bin/env bash
# build_nginx.sh — build a minimal nginx into a user prefix (no root).
#
# Usage: lab/fpm/build_nginx.sh [version]
# Result: lab/fpm/runtime/nginx/sbin/nginx
set -euo pipefail

VER="${1:-1.26.3}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNTIME="$HERE/runtime"
SRC="$RUNTIME/src"
PREFIX="$RUNTIME/nginx"
JOBS="${JOBS:-$(nproc)}"

mkdir -p "$SRC"

if [ ! -d "$SRC/nginx-$VER" ]; then
    TARBALL="$SRC/nginx-$VER.tar.gz"
    if [ ! -f "$TARBALL" ]; then
        echo "[*] downloading nginx-$VER"
        curl -fsSL -o "$TARBALL" "https://nginx.org/download/nginx-$VER.tar.gz"
    fi
    echo "[*] extracting $TARBALL"
    tar xzf "$TARBALL" -C "$SRC"
fi

cd "$SRC/nginx-$VER"
if [ ! -f Makefile ] || ! grep -q "$PREFIX" Makefile 2>/dev/null; then
    echo "[*] configuring nginx-$VER (no pcre/zlib deps)"
    ./configure \
        --prefix="$PREFIX" \
        --without-http_gzip_module \
        --without-http_rewrite_module \
        --without-http_charset_module \
        --without-http_ssi_module \
        --without-http_userid_module \
        --without-http_access_module \
        --without-http_auth_basic_module \
        --without-http_autoindex_module \
        --without-http_geo_module \
        --without-http_map_module \
        --without-http_split_clients_module \
        --without-http_referer_module \
        --without-http_proxy_module \
        --with-cc-opt="-O2" >/dev/null
fi
echo "[*] building nginx-$VER (-j$JOBS)"
make -j"$JOBS" >/dev/null
# `make install` would lay out conf/ and logs/ under the prefix; that is all we need.
make install >/dev/null
echo "[+] nginx ready: $PREFIX/sbin/nginx"
"$PREFIX/sbin/nginx" -v
