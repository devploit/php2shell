#!/usr/bin/env python3
"""
php2shell_offsets.py — extract libphp symbol offsets from PHP Docker images.

This fills the offset inventory for builds that have not been heap-calibrated.
It does not run the image: it creates a container, copies
/usr/lib/apache2/modules/libphp.so out, parses the ELF symbol table and writes
profiles/offsets/<version>-<arch>.json plus docs/offset-inventory.md.

Offsets alone do not give RCE. They are the per-build constants needed once a
heap profile exists; the dispatcher only runs verified profiles.

Usage:
    python3 tools/php2shell_offsets.py
    python3 tools/php2shell_offsets.py --images php:7.4-apache php:8.1-apache
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import os
import platform
import re
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OUT = os.path.join(ROOT, "profiles", "offsets")
DOC = os.path.join(ROOT, "docs", "offset-inventory.md")

DEFAULT_IMAGES = [
    "php:7.4-apache",
    "php:8.0-apache",
    "php:8.1-apache",
    "php:8.2.34-apache",
    "php:8.3.35-apache",
    "php:8.4.26-apache",
    "php:8.5.11-apache",
    # Real-world subversions inside the vulnerable windows (same list as
    # BUILDS in php2shell_matrix.py; pulled via a registry mirror when the
    # Hub is rate-limited).
    "php:8.4.2-apache",
    "php:8.4.5-apache",
    "php:8.4.6-apache",
    "php:8.4.7-apache",
    "php:8.4.8-apache",
    "php:8.4.10-apache",
    "php:8.4.11-apache",
    "php:8.4.12-apache",
    "php:8.4.13-apache",
    "php:8.4.14-apache",
    "php:8.4.15-apache",
    "php:8.4.16-apache",
    "php:8.4.17-apache",
    "php:8.4.18-apache",
    "php:8.4.19-apache",
    "php:8.4.20-apache",
    "php:8.4.25-apache",
    "php:8.5.0-apache",
    "php:8.5.1-apache",
    "php:8.5.2-apache",
    "php:8.5.3-apache",
    "php:8.5.4-apache",
    "php:8.5.5-apache",
    "php:8.5.6-apache",
    "php:8.5.7-apache",
    "php:8.5.8-apache",
    "php:8.5.9-apache",
    "php:8.5.10-apache",
]

LIB_PATHS = [
    "/usr/lib/apache2/modules/libphp.so",
    "/usr/lib/apache2/modules/libphp7.so",
    "/usr/lib/apache2/modules/libphp5.so",
]

SHT_SYMTAB = 2
SHT_DYNSYM = 11
PT_LOAD = 1


def docker(*args, timeout=900, text=True):
    return subprocess.run(["docker", *args], capture_output=True, text=text, timeout=timeout)


def parse_elf(path: str):
    with open(path, "rb") as handle:
        data = handle.read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not a little-endian ELF64 file")
    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)

    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from("<I", data, off)
        p_vaddr, = struct.unpack_from("<Q", data, off + 16)
        p_memsz, = struct.unpack_from("<Q", data, off + 40)
        if p_type == PT_LOAD and p_memsz:
            loads.append(p_vaddr)
    bias = min(loads) if loads else 0

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name_off, sh_type = struct.unpack_from("<II", data, off)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, off + 24)
        sh_link, = struct.unpack_from("<I", data, off + 40)
        sh_entsize, = struct.unpack_from("<Q", data, off + 56)
        sections.append({"type": sh_type, "offset": sh_offset, "size": sh_size,
                         "link": sh_link, "entsize": sh_entsize})

    wanted = {"zif_system": None, "zval_ptr_dtor": None, "ps_globals": None}
    for sec in sections:
        if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if sec["link"] >= len(sections):
            continue
        strtab = sections[sec["link"]]
        entsize = sec["entsize"] or 24
        for i in range(sec["size"] // entsize):
            off = sec["offset"] + i * entsize
            st_name, = struct.unpack_from("<I", data, off)
            st_value, = struct.unpack_from("<Q", data, off + 8)
            if not st_name:
                continue
            name_off = strtab["offset"] + st_name
            end = data.find(b"\x00", name_off)
            if end < 0:
                continue
            name = data[name_off:end].decode("ascii", "replace")
            if name in wanted and wanted[name] is None:
                wanted[name] = st_value
    return bias, wanted


def image_env(image: str) -> dict:
    out = docker("inspect", "--format",
                 "{{range .Config.Env}}{{println .}}{{end}}", image)
    env = {}
    for line in out.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def image_arch(image: str) -> str:
    # Some imported/emulated images report an empty Architecture, so ask the
    # image itself. uname inside the container is authoritative.
    out = docker("run", "--rm", "--entrypoint", "uname", image, "-m", timeout=120)
    machine = out.stdout.strip().lower()
    if machine:
        mapped = {"aarch64": "aarch64", "arm64": "aarch64",
                  "x86_64": "amd64", "amd64": "amd64"}.get(machine)
        if mapped:
            return mapped
    out = docker("inspect", "--format", "{{.Architecture}}", image)
    arch = out.stdout.strip()
    if not arch or arch == "unknown":
        machine = platform.machine().lower()
        arch = {"aarch64": "aarch64", "arm64": "aarch64", "x86_64": "amd64"}.get(machine, machine)
    return arch


def extract(image: str) -> dict:
    name = "p2s-off-" + image.replace(":", "-").replace("/", "-")
    docker("rm", "-f", name)
    print(f"[*] {image}: creating container", flush=True)
    created = docker("create", "--name", name, image, timeout=900)
    if created.returncode != 0:
        return {"image": image, "status": "pull/create failed",
                "error": created.stderr.strip()[:200]}
    try:
        lib = None
        for candidate in LIB_PATHS:
            target = f"/tmp/{name}.so"
            cp = docker("cp", f"{name}:{candidate}", target)
            if cp.returncode == 0:
                lib = target
                break
        if not lib:
            return {"image": image, "status": "libphp not found"}
        bias, symbols = parse_elf(lib)
        with open(lib, "rb") as handle:
            sha = hashlib.sha256(handle.read()).hexdigest()
        env = image_env(image)
        version = env.get("PHP_VERSION", "")
        if not version:
            tag = re.search(r"php:(\d+\.\d+\.\d+)", image)
            version = tag.group(1) if tag else ""
        arch = image_arch(image)
        result = {
            "image": image,
            "php_version": version,
            "branch": ".".join(version.split(".")[:2]) if version else "",
            "arch": arch,
            "libphp": {k: (hex(v) if v is not None else None) for k, v in symbols.items()},
            "libphp_sha256": sha,
            "status": "offsets extracted; heap not calibrated",
        }
        os.makedirs(OUT, exist_ok=True)
        path = os.path.join(OUT, f"{version or name}-{arch}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
        result["file"] = os.path.relpath(path, ROOT)
        print(f"    PHP {version} {arch}: zif={result['libphp']['zif_system']} "
              f"dtor={result['libphp']['zval_ptr_dtor']}", flush=True)
        return result
    finally:
        docker("rm", "-f", name)


def heap_status(version: str, arch: str) -> str | None:
    """Cross-reference profiles/ for a heap calibration of this build.

    Only calibrations against official images count: those profiles are named
    <version>-<distro>-<arch>.json (or <version>-bookworm-<arch>.json from the
    author's runs). Lab builds such as 8.3.0-bookworm.json use a different
    libphp binary and must not vouch for the official image.
    """
    best = None
    for path in glob.glob(os.path.join(ROOT, "profiles", f"*-{arch}.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                p = json.load(fh)
        except (OSError, ValueError):
            continue
        if p.get("php_version") != version or p.get("arch") != arch:
            continue
        rank = (3 if p.get("rce") else
                2 if p.get("measured", {}).get("libphp_base") else
                1 if p.get("measured", {}).get("chunk_base") else 0)
        if best is None or rank > best[0]:
            best = (rank, p)
    if best is None:
        return None
    return {3: "heap calibrated; RCE verified",
            2: "heap calibrated; leaks only",
            1: "heap calibrated; stage-1 leak only",
            0: "heap calibrated; leak not reproduced"}[best[0]]


def write_doc(results) -> None:
    entries = {}
    for path in glob.glob(os.path.join(OUT, "*.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                item = json.load(fh)
        except (OSError, ValueError):
            continue
        entries[(item.get("php_version"), item.get("arch"), item.get("image"))] = item
    for item in results:
        if item.get("libphp"):
            entries[(item.get("php_version"), item.get("arch"), item.get("image"))] = item
    ordered = sorted(entries.values(),
                     key=lambda r: tuple(int(x) if x.isdigit() else 0
                                         for x in (r.get("php_version") or "0").split(".")))
    lines = [
        "# libphp offset inventory",
        "",
        "Generated by `tools/php2shell_offsets.py`. These are symbol offsets only:",
        "a build still needs heap calibration before the chain can run.",
        "",
        "| Image | PHP | Arch | `zif_system` | `zval_ptr_dtor` | libphp sha256 | Status |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in ordered:
        lib = r.get("libphp") or {}
        status = heap_status(r.get("php_version", "?"), r.get("arch", "?")) \
            or r.get("status", "")
        lines.append("| {image} | {php} | {arch} | {zif} | {dtor} | {sha} | {status} |".format(
            image=r.get("image", ""), php=r.get("php_version", "?"),
            arch=r.get("arch", "?"), zif=lib.get("zif_system") or "-",
            dtor=lib.get("zval_ptr_dtor") or "-",
            sha=(r.get("libphp_sha256") or "-")[:12], status=status))
    lines += ["", "## Notes", "",
              "- Offsets are relative to the `libphp.so` load base; ASLR changes the base, not the offset.",
              "- The same PHP version built by another distribution/arch has different offsets.",
              "- Heap parameters (`stage1_n`, forge length, `htdata`, pads) are not included here;",
              "  run `tools/php2shell_calibrate.py` against a replica of the build for those.",
              ""]
    os.makedirs(os.path.dirname(DOC), exist_ok=True)
    with open(DOC, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract libphp offsets from PHP images.")
    ap.add_argument("--images", nargs="*", default=DEFAULT_IMAGES)
    args = ap.parse_args()
    if not shutil.which("docker"):
        print("docker not found", file=sys.stderr)
        return 4
    results = [extract(image) for image in args.images]
    write_doc(results)
    print(f"[*] wrote {DOC}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
