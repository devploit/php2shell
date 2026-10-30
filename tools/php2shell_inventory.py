#!/usr/bin/env python3
"""Inventory the generated PHP2Shell profiles.

Reads every JSON profile in profiles/ and prints the offsets and heap
parameters in a table (or as JSON). Profiles with rce=false are included and
clearly marked: they are calibrated leaks, not verified RCE.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
PROFILES = os.path.join(ROOT, "profiles")

COLUMNS = ("PHP", "build", "zif_system", "zval_ptr_dtor", "htdata",
           "stage1_n", "forge", "stage2_t", "stage3", "RCE")


def load_profiles(directory: str):
    rows = []
    for path in sorted(glob.glob(os.path.join(directory, "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        if not isinstance(data, dict) or "php_version" not in data:
            continue
        lib = data.get("libphp") or {}
        stages = data.get("stages") or {}
        rows.append({
            "php": data.get("php_version", ""),
            "build": data.get("name", ""),
            "zif_system": lib.get("zif_system") or "-",
            "zval_ptr_dtor": lib.get("zval_ptr_dtor") or "-",
            "htdata": lib.get("htdata") or "-",
            "stage1_n": stages.get("stage1_n") if stages.get("stage1_n") is not None else "-",
            "forge": stages.get("stage1_forge_len") if stages.get("stage1_forge_len") is not None else "-",
            "stage2_t": stages.get("stage2_t") if stages.get("stage2_t") is not None else "-",
            "stage3": stages.get("stage3_mode") or "-",
            "rce": bool(data.get("rce")),
            "status": data.get("status", ""),
            "file": os.path.relpath(path, ROOT),
        })
    rows.sort(key=lambda r: tuple(int(x) if x.isdigit() else 0 for x in r["php"].split(".")))
    return rows


def main() -> int:
    ap = argparse.ArgumentParser(description="List generated PHP2Shell profiles.")
    ap.add_argument("--profiles", default=PROFILES)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    rows = load_profiles(args.profiles)
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0

    widths = {c: max(len(c), *(len(str(r.get(c.lower(), ""))) for r in rows)) if rows else len(c)
              for c in COLUMNS}
    header = "  ".join(c.ljust(widths[c]) for c in COLUMNS)
    print(header)
    print("  ".join("-" * widths[c] for c in COLUMNS))
    for r in rows:
        print("  ".join([
            r["php"].ljust(widths["PHP"]),
            r["build"].ljust(widths["build"]),
            str(r["zif_system"]).ljust(widths["zif_system"]),
            str(r["zval_ptr_dtor"]).ljust(widths["zval_ptr_dtor"]),
            str(r["htdata"]).ljust(widths["htdata"]),
            str(r["stage1_n"]).ljust(widths["stage1_n"]),
            str(r["forge"]).ljust(widths["forge"]),
            str(r["stage2_t"]).ljust(widths["stage2_t"]),
            str(r["stage3"]).ljust(widths["stage3"]),
            ("yes" if r["rce"] else "no").ljust(widths["RCE"]),
        ]))
    verified = sum(1 for r in rows if r["rce"])
    print(f"\n{len(rows)} profiles, {verified} with verified RCE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
