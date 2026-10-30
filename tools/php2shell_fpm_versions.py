#!/usr/bin/env python3
"""PHP version registry for the CVE-2026-109619 (php2shell) FPM chain.

The upstream fix (released 2026-10-21) adds ``php_basic_early_rinit()``,
called from ``php_request_startup()`` *before* the request body is parsed.
It memsets ``BG(unserialize)``, so the pre-RINIT rfc1867 session decode of
consumer B sees a clean var_hash instead of producer A's stale one.

Upstream patched the supported branches only:

    8.2.35, 8.3.36, 8.4.27

Every earlier release of those branches is vulnerable.  (PHP 8.5 is fixed in
8.5.12 but is deliberately out of scope for this repository.)  PHP 8.1 and
older
(including 7.x) are end-of-life and never receive a fix: there is no
release of those branches that is not vulnerable.

This module is the single source of truth for that matrix; the lab, the
profile generator, and the calibration harness all resolve versions through
it.  The source-level detector (:func:`source_is_fixed`) checks for the
symbol the fix introduced, so a new tarball or a distro backport can be
classified without trusting a version string.
"""

from __future__ import annotations

import os
import re
import subprocess
import tarfile

VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")

# Branches this repository tracks.  "fixed_in" is the first release that
# contains php_basic_early_rinit(); "last_release" is the newest release of
# the branch (== the last vulnerable one for the patched branches, and the
# EOL final release for the unpatched ones).
#
# slot: deterministic lab port block, see ports_for().
BRANCHES: dict[str, dict] = {
    "7.2": {"fixed_in": None, "last_release": "7.2.34", "slot": 0},
    "7.4": {"fixed_in": None, "last_release": "7.4.33", "slot": 1},
    # EOL and never patched: 8.0/8.1 are chain-verified (7.4+ mechanism);
    # 5.x has no zend_reference to forge, so the plant is its chain.
    "8.0": {"fixed_in": None, "last_release": "8.0.30", "slot": 6},
    "8.1": {"fixed_in": None, "last_release": "8.1.33", "slot": 7},
    "8.2": {"fixed_in": "8.2.35", "last_release": "8.2.34", "slot": 2},
    "8.3": {"fixed_in": "8.3.36", "last_release": "8.3.35", "slot": 3},
    "8.4": {"fixed_in": "8.4.27", "last_release": "8.4.26", "slot": 4},
}

# Branches that are vulnerable and were never patched at all.  Listed for
# documentation; every branch without a "fixed_in" release behaves the same.
EOL_BRANCHES: tuple[str, ...] = ("5.x", "7.x", "8.0", "8.1")  # never patched

# session.upload_progress exists from PHP 5.4 on, so 5.0-5.3 have no attack
# surface for either chain of this advisory
UPLOAD_PROGRESS_FROM = (5, 4)

# The lab keeps the historical port assignment of the first three builds so
# the documented URLs (README, CI) stay stable.
LEGACY_PORTS: dict[str, tuple[int, int, int, int]] = {
    "8.4.25": (8130, 8131, 9021, 9022),
    "8.4.26": (8110, 8111, 9001, 9002),
    "8.4.27": (8120, 8121, 9011, 9012),
}

_SLOT_BLOCK = 100
_SLOT_BASE_HTTP = 8200
_SLOT_BASE_FPM = 9200


class UnknownVersion(ValueError):
    """The version string is not a version this registry can classify."""


def parse(version: str) -> tuple[int, int, int]:
    """Split ``8.4.26`` into ``(8, 4, 26)``; raise UnknownVersion otherwise."""
    match = VERSION_RE.match(version)
    if not match:
        raise UnknownVersion(f"not a PHP version: {version!r}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def branch_of(version: str) -> str:
    """Return the branch of a version, for example ``8.4`` for ``8.4.26``."""
    major, minor, _patch = parse(version)
    return f"{major}.{minor}"


def known_branch(version: str) -> bool:
    """True when the version belongs to a branch this registry tracks."""
    return branch_of(version) in BRANCHES


def fixed_in(version: str) -> str | None:
    """First release of the version's branch that contains the fix.

    Returns ``None`` for branches upstream never patched (EOL).
    """
    return BRANCHES.get(branch_of(version), {}).get("fixed_in")


def is_vulnerable(version: str) -> bool:
    """True when a release predates the fix of its branch.

    Versions of unpatched (EOL) branches are always vulnerable: no release
    of those branches can contain the fix.
    """
    patch = fixed_in(version)
    if patch is None:
        return True
    return parse(version) < parse(patch)


def is_fixed(version: str) -> bool:
    """True when the release contains ``php_basic_early_rinit()``."""
    return not is_vulnerable(version)


def affected_versions() -> list[str]:
    """The newest vulnerable release of every tracked branch, oldest first."""
    out = []
    for branch, meta in sorted(BRANCHES.items()):
        last = meta["last_release"]
        if meta["fixed_in"] is None:
            out.append(last)
        else:
            out.extend(f"{branch}.{n}" for n in range(0, parse(last)[2] + 1))
    return out


def ports_for(version: str) -> tuple[int, int, int, int]:
    """Return ``(chain_http, builder_http, chain_fpm, builder_fpm)``.

    Known lab builds keep their historical ports; every other version gets a
    deterministic block derived from its branch and patch level, so the lab
    can run any pair of versions side by side without a port collision.
    """
    legacy = LEGACY_PORTS.get(version)
    if legacy:
        return legacy
    branch = branch_of(version)
    meta = BRANCHES.get(branch)
    if meta is None:
        raise UnknownVersion(
            f"no port block for branch {branch} (known: {sorted(BRANCHES)})")
    slot = meta["slot"] * _SLOT_BLOCK + parse(version)[2] * 2
    return (_SLOT_BASE_HTTP + slot, _SLOT_BASE_HTTP + slot + 1,
            _SLOT_BASE_FPM + slot, _SLOT_BASE_FPM + slot + 1)


def source_is_fixed(source: str) -> bool:
    """Classify a PHP source tree or release tarball by its fix marker.

    The upstream fix introduced ``php_basic_early_rinit()``; a build without
    it keeps the stale ``BG(unserialize)`` state this chain relies on.
    """
    if os.path.isdir(source):
        path = os.path.join(source, "ext", "standard", "basic_functions.c")
        with open(path, encoding="utf-8", errors="replace") as handle:
            return "php_basic_early_rinit" in handle.read()
    with tarfile.open(source, "r:*") as tar:
        for member in tar.getmembers():
            if not member.name.endswith("ext/standard/basic_functions.c"):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                break
            return b"php_basic_early_rinit" in handle.read()
    raise UnknownVersion(f"no ext/standard/basic_functions.c in {source}")


def has_session_cancel_decode(source: str) -> bool:
    """True when the build tears the session down on a decode bailout.

    ``php_session_decode`` wraps the serializer in ``zend_try/zend_catch``
    and calls ``php_session_cancel_decode()`` -> ``php_session_destroy()``,
    which unlinks the session file the OOM was decoding.  The struct the
    chain reclaims is *not* freed there: ``BG(unserialize).data`` is an
    emalloc block that the Zend memory manager releases at request end on
    every PHP version, and the reuse logic in ``php_var_unserialize_init``
    predates 8.2 as well - so the chain applies from PHP 7.4 on (verified
    end to end on 7.4.33, 8.0.30 and 8.1.33).  This detector remains the
    marker for the unlink side effect, which the
    rebuild-every-iteration logic relies on: an 8.2+ arm destroys the
    session file, older builds keep it.
    """
    if os.path.isdir(source):
        path = os.path.join(source, "ext", "session", "session.c")
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    else:
        with tarfile.open(source, "r:*") as tar:
            text = ""
            for member in tar.getmembers():
                if member.name.endswith("ext/session/session.c"):
                    handle = tar.extractfile(member)
                    if handle is not None:
                        text = handle.read().decode("utf-8", "replace")
                    break
    return "php_session_cancel_decode" in text


def chain_applies(version: str) -> bool:
    """Whether this repository's chain can apply to a version at all.

    The stale ``BG(unserialize)`` state after a post-RINIT OOM is left
    behind on every branch from PHP 7.4 up: ``php_var_unserialize_init``
    reuses ``BG(unserialize).data`` whenever ``level > 0``, the Zend
    memory manager frees that emalloc block at request end, and
    ``php_session_cancel_decode`` (8.2+) only unlinks the session file -
    it never touches the struct.  Verified end to end (RCE over HTTP)
    on 7.4.33, 8.0.30, 8.1.33, 8.2.34, 8.3.35 and the 8.4/8.5 branches.

    7.2 arms the stale state too, but no reclaim shape covers the struct
    on its allocator yet, so 7.2 and 5.x stay on the session-file plant
    until a run proves them.

    A real build can still be classified with
    :func:`has_session_cancel_decode`, which reads the source instead of
    trusting the version.
    """
    major, minor, _patch = parse(version)
    return (major, minor) >= (7, 4)


def build_status(binary: str) -> str:
    """Return the version string a php-fpm binary reports."""
    proc = subprocess.run([binary, "-v"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"{binary} -v failed: {proc.stderr.strip()}")
    match = re.search(r"PHP (\d+\.\d+\.\d+)", proc.stdout)
    if not match:
        raise RuntimeError(f"cannot parse version from {proc.stdout!r}")
    return match.group(1)
