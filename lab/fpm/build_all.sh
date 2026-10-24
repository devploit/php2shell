#!/usr/bin/env bash
# build_all.sh — build several PHP-FPM versions into the lab runtime.
#
# Usage: lab/fpm/build_all.sh <version> [<version> ...]
#        lab/fpm/build_all.sh --range 8.4.0-8.4.26
#
# Environment:
#   PAR   parallel build jobs (default: 4)
#   JOBS  make -j per build (default: 4)
#
# Each build reuses lab/fpm/build_php.sh, so the sources are downloaded once
# and the user prefix lands in lab/fpm/runtime/php-<version>/.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PAR="${PAR:-4}"
JOBS="${JOBS:-4}"
LOGDIR="${LOGDIR:-$HERE/runtime/logs/builds}"

mkdir -p "$LOGDIR"

expand_range() {
    # 8.4.0-8.4.26 -> 8.4.0 ... 8.4.26
    local spec="$1" first last prefix v
    first="${spec%%-*}"
    last="${spec##*-}"
    prefix="${first%.*}."
    for ((v = ${first##*.}; v <= ${last##*.}; v++)); do
        printf '%s%d\n' "$prefix" "$v"
    done
}

VERSIONS=()
for arg in "$@"; do
    case "$arg" in
        --range) continue ;;
        *-*)
            while IFS= read -r line; do VERSIONS+=("$line"); done \
                < <(expand_range "$arg")
            ;;
        *) VERSIONS+=("$arg") ;;
    esac
done

if [ ${#VERSIONS[@]} -eq 0 ]; then
    echo "usage: build_all.sh <version> [<version> ...] | --range 8.4.0-8.4.26"
    exit 2
fi

running=0
failures=0
for version in "${VERSIONS[@]}"; do
    prefix="$HERE/runtime/php-$version"
    if [ -x "$prefix/sbin/php-fpm" ]; then
        echo "[=] $version: already built"
        continue
    fi
    while [ "$(jobs -rp | wc -l)" -ge "$PAR" ]; do wait -n; done
    (
        log="$LOGDIR/build-$version.log"
        if "$HERE/build_php.sh" "$version" >"$log" 2>&1; then
            echo "[+] $version: built"
        else
            echo "[!] $version: build failed (see $log)"
            exit 1
        fi
    ) &
    running=$((running + 1))
done
wait

for version in "${VERSIONS[@]}"; do
    prefix="$HERE/runtime/php-$version"
    if [ ! -x "$prefix/sbin/php-fpm" ]; then
        echo "[!] $version: missing $prefix/sbin/php-fpm"
        failures=$((failures + 1))
    fi
done

if [ "$failures" -gt 0 ]; then
    echo "[!] $failures build(s) failed"
    exit 1
fi
echo "[+] all requested versions built"
