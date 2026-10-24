#!/usr/bin/env python3
"""Generate a draft FPM profile from a PHP-FPM build.

The generator collects everything that is version specific and machine
readable:

* ``nm`` on the php-fpm binary for ``zif_system``, ``zval_ptr_dtor`` and
  ``basic_globals``;
* the struct layouts (php_basic_globals, zend_array, zend_reference,
  zend_string, zend_execute_data) compiled from the build's own headers by
  ``tools/php2shell_fpm_offsets.c``;
* the ``php_unserialize_data`` layout parsed from the PHP source tree.

A generated profile is intentionally marked ``verified: false`` and
``rce: false``: symbols and layouts do not prove the heap geometry, so it
must still be calibrated against a lab with ``leak``/``primitive``/``endgame``
before it is trusted.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.dirname(os.path.abspath(__file__))
RUNTIME = os.path.join(ROOT, "lab", "fpm", "runtime")
SYMBOLS = ("zif_system", "zval_ptr_dtor", "basic_globals")
OFFSETS_C = os.path.join(HERE, "php2shell_fpm_offsets.c")

# branch -> first release that carries the fix.  PHP 8.1 and older (7.x
# included) are end-of-life: upstream never patched them, so every release
# of those branches is vulnerable and the profile records UNPATCHED.
FIXED_IN = {
    "7.2": None,
    "7.4": None,
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
}

UNPATCHED = "none (EOL branch, no upstream fix)"

# fallback layout (PHP 8.4) used when a build has no headers or source
DEFAULT_LAYOUT = {
    "unserialize_data": {
        "last": 0, "first_dtor": 8, "last_dtor": 16, "allowed_classes": 24,
        "ref_props": 32, "cur_depth": 40, "max_depth": 48, "entries": 56,
        "size": 8216,
    },
    "var_entries": {"used_slots": 0, "next": 8, "data": 16, "max": 1018},
    "zval": {"value": 0, "type_info": 8, "context": 12, "size": 16},
    "zend_array": {"gc": 0, "flags": 8, "nTableMask": 12, "arData": 16,
                   "nNumUsed": 24, "nNumOfElements": 28, "nTableSize": 32,
                   "pDestructor": 48},
    "zend_reference": {"gc": 0, "val": 8, "val_type_info": 16, "sources": 24},
    "zend_string": {"gc": 0, "h": 8, "len": 16, "val": 24},
    "zend_execute_data": {"opline": 0, "call": 8, "return_value": 16,
                          "func": 24, "num_args": 44, "arg1": 80},
    "bucket": {"val": 0, "h": 16, "key": 24},
}


def parse_nm(text: str) -> dict[str, int]:
    """Return the offsets of the required symbols from ``nm -n`` output.

    Older releases export some symbols under a different name (PHP <= 7.2
    prefixes the zval destructor with an underscore), so every alias of a
    symbol resolves to its canonical key.
    """
    found: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        address, name = parts[0], parts[2]
        if name not in SYMBOLS or name in found:
            continue
        try:
            found[name] = int(address, 16)
        except ValueError:
            continue
    missing = [name for name in SYMBOLS if name not in found]
    if missing:
        raise ValueError(f"missing symbols: {', '.join(missing)}")
    return found


def read_symbols(binary: str) -> dict[str, int]:
    proc = subprocess.run(["nm", "-n", binary], capture_output=True, text=True)
    if proc.returncode != 0:
        detail = proc.stderr.strip() or f"nm exited {proc.returncode}"
        raise RuntimeError(f"cannot read symbols from {binary}: {detail}")
    return parse_nm(proc.stdout)


# --------------------------------------------------------------------------- #
# struct layouts
# --------------------------------------------------------------------------- #

def compile_offsets(prefix: str) -> dict:
    """Compile the offsets helper against a build's headers and run it."""
    include = os.path.join(prefix, "include", "php")
    if not os.path.isdir(include):
        raise RuntimeError(f"no PHP headers under {include}")
    cc = os.environ.get("CC", "cc")
    with tempfile.TemporaryDirectory() as tmp:
        binary = os.path.join(tmp, "offsets")
        cmd = [
            cc, "-O0", "-o", binary, OFFSETS_C,
            f"-I{include}", f"-I{os.path.join(include, 'main')}",
            f"-I{os.path.join(include, 'Zend')}", f"-I{os.path.join(include, 'TSRM')}",
            f"-I{os.path.join(include, 'ext')}",
            f"-I{os.path.join(include, 'ext', 'date', 'lib')}",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout).strip().splitlines()
            tail = "\n".join(detail[-8:])
            raise RuntimeError(f"offsets helper failed to compile:\n{tail}")
        run = subprocess.run([binary], capture_output=True, text=True)
        if run.returncode != 0:
            raise RuntimeError(f"offsets helper failed: {run.stderr.strip()}")
        return json.loads(run.stdout)


_UNSERIALIZE_FIELDS = ("last", "first_dtor", "last_dtor", "allowed_classes",
                       "ref_props", "cur_depth", "max_depth", "entries")


def parse_unserialize_struct(source_dir: str) -> dict:
    """Parse ``struct php_unserialize_data`` from the PHP source tree.

    The struct is private to ext/standard/var_unserializer.c, so the offsets
    are derived from the source.  Two shapes exist:

    The struct embeds a ``var_entries entries`` block, so it is 8216 bytes
    and ``last`` points at its own embedded block.
    """
    candidates = []
    for relative in ("ext/standard/var_unserializer.c",
                     "ext/standard/var_unserializer.re",
                     "ext/standard/php_var.c"):
        path = os.path.join(source_dir, relative)
        if os.path.isfile(path):
            candidates.append(path)
    if not candidates:
        raise RuntimeError(f"no var_unserializer source under {source_dir}")

    text = ""
    for path in candidates:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        if "struct php_unserialize_data" in text:
            break

    match = re.search(r"struct php_unserialize_data\s*\{(.*?)\n\};", text, re.S)
    if not match:
        raise RuntimeError("php_unserialize_data definition not found")
    body = match.group(1)

    # every member is a pointer or a zend_long: 8 bytes on the 64-bit builds
    # this repository supports
    members: list[str] = []
    for line in body.splitlines():
        line = line.split("/*")[0].strip()
        if not line or line.startswith("//") or not line.endswith(";"):
            continue
        declaration = line[:-1].strip()
        if not declaration:
            continue
        name = declaration.split()[-1].lstrip("*").split("[")[0]
        members.append(name)

    if not members:
        raise RuntimeError("php_unserialize_data has no members")
    offsets = {name: 8 * index for index, name in enumerate(members)}

    max_match = re.search(r"#define\s+VAR_ENTRIES_MAX\s+(\d+)", text)
    if not max_match:
        raise RuntimeError("VAR_ENTRIES_MAX not found")
    entries_max = int(max_match.group(1))

    if "entries" not in offsets:
        raise RuntimeError("php_unserialize_data has no entries member")
    # embedded block: var_entries {used_slots, next, zval *data[MAX]}
    var_entries = {"used_slots": 0, "next": 8, "data": 16,
                   "max": entries_max}
    size = offsets["entries"] + 16 + 8 * entries_max

    return {
        "offsets": offsets,
        "var_entries": var_entries,
        "size": size,
    }


def build_layout(prefix: str, source_dir: str | None) -> dict:
    """Full layout dictionary for a build."""
    layout = copy.deepcopy(DEFAULT_LAYOUT)
    try:
        offsets = compile_offsets(prefix)
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"[!] offsets helper: {exc}", file=sys.stderr)
        offsets = {}
    if offsets:
        layout["bg"] = {
            "unserialize_data": offsets["bg"]["unserialize_data"],
            "unserialize_level": offsets["bg"]["unserialize_level"],
        }
        for key in ("zval", "zend_array", "zend_reference", "zend_string",
                    "zend_execute_data", "bucket"):
            if key in offsets:
                layout[key] = offsets[key]
    if source_dir:
        try:
            parsed = parse_unserialize_struct(source_dir)
        except (RuntimeError, OSError) as exc:
            print(f"[!] unserialize layout: {exc}", file=sys.stderr)
        else:
            # the parse covers every member of the struct, so it replaces the
            # defaults instead of merging into them: PHP <= 7.3 has no
            # cur_depth/max_depth and no embedded entries block at all
            layout["unserialize_data"] = dict(parsed["offsets"])
            layout["unserialize_data"]["size"] = parsed["size"]
            layout["var_entries"] = parsed["var_entries"]
    return layout


# --------------------------------------------------------------------------- #
# profiles
# --------------------------------------------------------------------------- #

def build_draft(version: str, symbols: dict[str, int], template: dict,
                distro: str = "debian", arch: str = "amd64",
                fixed_in: str | None = None,
                layout: dict | None = None) -> dict:
    profile = copy.deepcopy(template)
    branch = ".".join(version.split(".")[:2])
    profile.update({
        "name": f"php-{version}-fpm",
        "php_version": version,
        "branch": branch,
        "fixed_in": fixed_in or FIXED_IN.get(branch, "unknown") or UNPATCHED,
        "verified": False,
        "rce": False,
        "distro": distro,
        "arch": arch,
        "status": (
            "Draft profile: symbols extracted with nm and struct layouts "
            "derived from the build headers/source; allocator, reclaim, "
            "no-oracle, and leak geometry copied from the template and NOT "
            "calibrated. Run leak/primitive/endgame in a lab and update the "
            "geometry and verified flags before trusting this profile."
        ),
    })
    profile["libphp"]["zif_system"] = hex(symbols["zif_system"])
    profile["libphp"]["zval_ptr_dtor"] = hex(symbols["zval_ptr_dtor"])
    profile["fpm"]["basic_globals"] = hex(symbols["basic_globals"])
    if layout:
        profile["layout"] = copy.deepcopy(layout)
        profile["fpm"]["bg_unserialize_data_off"] = \
            layout["bg"]["unserialize_data"]
        profile["fpm"]["bg_unserialize_level_off"] = \
            layout["bg"]["unserialize_level"]
        profile["fpm"]["struct_size"] = layout["unserialize_data"]["size"]
    return profile


def _render(value, indent: int = 0) -> str:
    """Render JSON with the small objects kept on a single line."""
    pad = "  " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        if all(not isinstance(v, (dict, list)) for v in value.values()):
            inner = ", ".join(f"{json.dumps(k)}: {json.dumps(v)}"
                              for k, v in value.items())
            return "{" + inner + "}"
        items = [f'{pad}  {json.dumps(k)}: {_render(v, indent + 1)}'
                 for k, v in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + pad + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        if all(not isinstance(v, (dict, list)) for v in value):
            return "[" + ", ".join(json.dumps(v) for v in value) + "]"
        items = [f'{pad}  {_render(v, indent + 1)}' for v in value]
        return "[\n" + ",\n".join(items) + "\n" + pad + "]"
    return json.dumps(value)


def dump_json(profile: dict, path: str) -> None:
    """Write a profile with the arrays of scalars kept on one line."""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(_render(profile))
        handle.write("\n")


def prefix_for(version: str) -> str:
    return os.path.join(RUNTIME, f"php-{version}")


def source_for(version: str) -> str | None:
    path = os.path.join(RUNTIME, "src", f"php-{version}")
    return path if os.path.isdir(path) else None


def built_versions() -> list[str]:
    if not os.path.isdir(RUNTIME):
        return []
    versions = []
    for name in os.listdir(RUNTIME):
        if name.startswith("php-") and os.path.isdir(os.path.join(RUNTIME, name)):
            version = name[4:]
            if os.path.isfile(os.path.join(RUNTIME, name, "sbin", "php-fpm")):
                versions.append(version)
    return sorted(versions, key=lambda v: [int(x) for x in v.split(".")])


def generate(version: str, template_path: str, output: str,
             distro: str, arch: str, fixed_in: str | None,
             force: bool) -> dict:
    prefix = prefix_for(version)
    binary = os.path.join(prefix, "sbin", "php-fpm")
    if not os.path.isfile(binary):
        raise RuntimeError(f"missing {binary}; build the version first")
    with open(template_path, encoding="utf-8") as handle:
        template = json.load(handle)
    symbols = read_symbols(binary)
    layout = build_layout(prefix, source_for(version))
    profile = build_draft(version, symbols, template, distro=distro,
                          arch=arch, fixed_in=fixed_in, layout=layout)
    if os.path.exists(output) and not force:
        raise RuntimeError(f"{output} exists; pass --force to overwrite")
    dump_json(profile, output)
    return {"profile": profile, "symbols": symbols, "layout": layout}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--php-fpm", default=None,
                        help="path to the php-fpm binary to inspect")
    parser.add_argument("--version", default=None,
                        help="PHP version, for example 8.4.25")
    parser.add_argument("--all", action="store_true",
                        help="generate a draft for every built version")
    parser.add_argument("--template",
                        default=os.path.join(ROOT, "profiles",
                                             "8.4.26-fpm.json"),
                        help="known-good profile to copy geometry from")
    parser.add_argument("--output", default=None,
                        help="output path (default profiles/<version>-fpm.json)")
    parser.add_argument("--distro", default="debian")
    parser.add_argument("--arch", default="amd64")
    parser.add_argument("--fixed-in", default=None)
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing output file")
    args = parser.parse_args()

    if args.all:
        versions = built_versions()
        if not versions:
            print(f"[!] no built versions under {RUNTIME}")
            return 1
    else:
        if not args.version:
            parser.error("--version is required (or use --all)")
        versions = [args.version]

    failures = 0
    for version in versions:
        output = args.output or os.path.join(
            ROOT, "profiles", f"{version}-fpm.json")
        if args.all and args.output:
            output = args.output
        try:
            result = generate(version, args.template, output, args.distro,
                              args.arch, args.fixed_in, args.force)
        except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
            print(f"[!] {version}: {exc}", file=sys.stderr)
            failures += 1
            continue
        symbols = result["symbols"]
        print(f"[+] wrote draft {output}")
        print(f"    zif_system=0x{symbols['zif_system']:x} "
              f"zval_ptr_dtor=0x{symbols['zval_ptr_dtor']:x} "
              f"basic_globals=0x{symbols['basic_globals']:x}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
