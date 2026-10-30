#!/usr/bin/env python3
"""
php2shell_labs.py — disposable local laboratories for the PHP builds in the
profile/offset inventory.

Each lab is an official PHP Apache image with:
  - display_errors=On, memory_limit=8M, post_max_size=512M (lab/rce/php.ini)
  - one prefork worker (lab/rce/apache.conf)
  - a minimal webroot (lab/rce/webroot)
  - a per-lab /out mount for the proof file

Commands:
    python3 tools/php2shell_labs.py up
    python3 tools/php2shell_labs.py status
    python3 tools/php2shell_labs.py test
    python3 tools/php2shell_labs.py down

`test` runs tools/php2shell_auto.py against every lab and reports RCE/no-RCE.
Only builds with a verified RCE profile will execute a command; the rest are
refused by the dispatcher.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import subprocess
import sys
import time
import urllib.request

from php2shell_paths import default_repo_dir, prepare_lab_out

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LAB = os.path.join(ROOT, "lab", "rce")
OUT = os.path.join(LAB, "out")
REPO = default_repo_dir()

BUILDS = [
    ("7.4.33", "php:7.4-apache", 8100),
    ("8.0.30", "php:8.0-apache", 8101),
    ("8.1.34", "php:8.1-apache", 8102),
    ("8.2.34", "php:8.2.34-apache", 8103),
    ("8.3.35", "php:8.3.35-apache", 8104),
    ("8.4.26", "php:8.4.26-apache", 8105),
    ("8.5.11", "php:8.5.11-apache", 8106),
    # Real-world subversions (mirror the matrix factory builds).
    ("8.2.28", "php:8.2.28-apache", 8120),
    ("8.3.20", "php:8.3.20-apache", 8121),
    ("8.4.2", "php:8.4.2-apache", 8122),
    ("8.4.5", "php:8.4.5-apache", 8123),
    ("8.4.10", "php:8.4.10-apache", 8124),
    ("8.4.20", "php:8.4.20-apache", 8125),
    ("8.4.25", "php:8.4.25-apache", 8126),
    ("8.5.0", "php:8.5.0-apache", 8127),
    ("8.5.5", "php:8.5.5-apache", 8128),
    ("8.5.10", "php:8.5.10-apache", 8129),
]


def docker(*args, timeout=900, capture=True):
    return subprocess.run(["docker", *args], capture_output=capture, text=True, timeout=timeout)


def name_for(version: str) -> str:
    return "p2s-lab-" + version.replace(".", "")


def wait_http(url: str, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def up(only=None):
    prepare_lab_out(OUT)
    for version, image, port in BUILDS:
        if only and version not in only:
            continue
        name = name_for(version)
        outdir = prepare_lab_out(os.path.join(OUT, version))
        docker("rm", "-f", name)
        print(f"[*] {version}: starting {image} on :{port}", flush=True)
        result = docker("run", "-d", "--name", name,
                        "-p", f"127.0.0.1:{port}:80",
                        "-v", f"{LAB}/webroot:/var/www/html:ro",
                        "-v", f"{LAB}/php.ini:/usr/local/etc/php/conf.d/zz-lab.ini:ro",
                        "-v", f"{LAB}/apache.conf:/etc/apache2/conf-enabled/zz-lab.conf:ro",
                        "-v", f"{outdir}:/out",
                        image)
        if result.returncode != 0:
            print(f"    failed: {result.stderr.strip()[:200]}")
            continue
        ok = wait_http(f"http://127.0.0.1:{port}/index.php")
        print(f"    {'ready' if ok else 'NOT responding'} -> http://127.0.0.1:{port}/")


def down():
    for version, _image, _port in BUILDS:
        docker("rm", "-f", name_for(version))


def status():
    for version, image, port in BUILDS:
        result = docker("inspect", "-f", "{{.State.Status}}", name_for(version))
        state = result.stdout.strip() if result.returncode == 0 else "absent"
        print(f"{version:8} {image:24} :{port}  {state}")


def test():
    results = []
    for version, _image, port in BUILDS:
        name = name_for(version)
        state = docker("inspect", "-f", "{{.State.Status}}", name).stdout.strip()
        if state != "running":
            results.append((version, "not running", ""))
            continue
        proof = os.path.join(OUT, version, "p1")
        with contextlib.suppress(OSError):
            os.unlink(proof)
        cmd = [sys.executable, os.path.join(HERE, "php2shell_auto.py"),
               "-u", f"http://127.0.0.1:{port}/index.php",
               "-c", "id>/out/p1", "--repo-dir", REPO,
               "--proof-file", proof, "--memory-limit-mb", "8"]
        print(f"\n=== {version} :{port} ===", flush=True)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        output = (result.stdout + result.stderr).strip().splitlines()
        print("\n".join(output[-6:]), flush=True)
        if result.returncode == 0 and os.path.isfile(proof):
            with open(proof) as handle:
                results.append((version, "RCE", handle.read().strip()))
        else:
            results.append((version, f"no RCE (exit {result.returncode})", ""))
    print("\n=== summary ===")
    for version, status_text, proof in results:
        print(f"  {version:8} {status_text:24} {proof}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Local PHP2Shell laboratories.")
    ap.add_argument("command", choices=("up", "down", "status", "test"))
    ap.add_argument("--only", default=None, help="comma-separated versions for 'up'")
    args = ap.parse_args()
    only = set(args.only.split(",")) if args.only else None
    if only is not None:
        unknown = sorted(only - {version for version, _image, _port in BUILDS})
        if unknown:
            print(f"unknown version(s) in --only: {', '.join(unknown)}", file=sys.stderr)
            print(f"available: {', '.join(v for v, _i, _p in BUILDS)}", file=sys.stderr)
            return 2
    if args.command == "up":
        up(only)
    elif args.command == "down":
        down()
    elif args.command == "status":
        status()
    else:
        test()
    return 0


if __name__ == "__main__":
    sys.exit(main())
