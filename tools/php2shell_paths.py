#!/usr/bin/env python3
"""Shared path resolution for the upstream PHP2Shell checkout."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor" / "php2shell-upstream"
FALLBACK = Path("/tmp/php2shell-rce")


def prepare_lab_out(path: str | Path) -> str:
    """Create a lab output directory the container user can write to."""
    target = Path(path)
    target.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        target.chmod(0o777)
    return str(target)


def default_repo_dir() -> str:
    """Prefer the bootstrapped checkout, then the historical /tmp clone."""
    env = os.environ.get("P2S_REPO_DIR")
    if env:
        return env
    if (VENDOR / "exploit.py").is_file():
        return str(VENDOR)
    return str(FALLBACK)
