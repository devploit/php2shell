#!/usr/bin/env bash
# build_php.sh — build a vulnerable/fixed PHP with FPM into a user prefix.
#
# Usage: lab/fpm/build_php.sh <version> [tarball]
#   e.g. lab/fpm/build_php.sh 8.4.26 /tmp/opencode/php-8.4.26.tar.gz
#
# The result is lab/fpm/runtime/php-<version>/{sbin/php-fpm,bin/php,...}.
# No root required.  Extensions kept minimal: session + standard (zif_system).
set -euo pipefail

VER="${1:?usage: build_php.sh <version> [tarball]}"
TARBALL="${2:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUNTIME="$HERE/runtime"
SRC="$RUNTIME/src"
PREFIX="$RUNTIME/php-$VER"
JOBS="${JOBS:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)}"

mkdir -p "$SRC"

download_tarball() {
    # A truncated download is a common failure mode: the archive is checked
    # with gzip -t and re-fetched until it is intact.
    local url tarball attempt
    tarball="$1"
    for attempt in 1 2 3; do
        rm -f "$tarball"
        for url in "https://www.php.net/distributions/php-$VER.tar.gz" \
                   "https://museum.php.net/php8/php-$VER.tar.gz"; do
            echo "[*] downloading php-$VER (attempt $attempt) from $url"
            if curl -fsSL -o "$tarball" "$url" && gzip -t "$tarball" 2>/dev/null; then
                return 0
            fi
            echo "[!] download or archive check failed for php-$VER"
        done
    done
    echo "[!] could not fetch a valid php-$VER tarball"
    return 1
}

if [ ! -d "$SRC/php-$VER" ]; then
    if [ -z "$TARBALL" ]; then
        TARBALL="$SRC/php-$VER.tar.gz"
        if [ ! -f "$TARBALL" ] || ! gzip -t "$TARBALL" 2>/dev/null; then
            download_tarball "$TARBALL"
        fi
    fi
    echo "[*] extracting $TARBALL"
    tar xzf "$TARBALL" -C "$SRC"
fi

# Legacy branches (7.x) mis-detect modern glibc in two places, both of which
# stop the build with a current toolchain:
#
#   * readdir_r() is the POSIX three-argument form since glibc 2.30, while
#     configure still selects the legacy two-argument one.  PHP 7.2 also
#     calls php_readdir_r() from ext/session/mod_files.c before including
#     php_reentrancy.h, so the macro that maps it onto readdir_r() cannot be
#     relied on: patch the call itself.
#   * the fopencookie seek handler takes a pointer to an off64_t, a plain
#     configure decision, so it is fixed in the generated php_config.h.
fix_legacy_config() {
    local cfg="$SRC/php-$VER/main/php_config.h"
    local reent="$SRC/php-$VER/main/reentrancy.c"
    [ -f "$cfg" ] || return 0
    if grep -q '^/\* #undef COOKIE_SEEKER_USES_OFF64_T \*/' "$cfg"; then
        sed -i 's|^/\* #undef COOKIE_SEEKER_USES_OFF64_T \*/|#define COOKIE_SEEKER_USES_OFF64_T 1|' \
            "$cfg"
    fi
    if [ -f "$reent" ] && grep -q '^	readdir_r(dirp, entry);$' "$reent"; then
        sed -i 's|^	readdir_r(dirp, entry);$|	struct dirent *r_dir_entry = NULL;\n	readdir_r(dirp, entry, \&r_dir_entry);|' \
            "$reent"
    fi
}

cd "$SRC/php-$VER"
if [ ! -f Makefile ] || [ ! -f config.status ]; then
    echo "[*] configuring php-$VER (fpm, session, minimal)"
    ./configure \
        --prefix="$PREFIX" \
        --disable-all \
        --enable-cli \
        --enable-fpm \
        --enable-session \
        --without-pear \
        --disable-cgi \
        --disable-phpdbg \
        CFLAGS="${CFLAGS:--O2 -g}"
fi
fix_legacy_config
echo "[*] building php-$VER (-j$JOBS)"
make -j"$JOBS" >/dev/null
make install >/dev/null
echo "[+] php-$VER ready: $PREFIX/sbin/php-fpm"
"$PREFIX/sbin/php-fpm" -v | head -1
