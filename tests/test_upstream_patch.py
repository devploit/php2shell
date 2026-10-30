#!/usr/bin/env python3
"""Tests for the runtime changes applied to the fetched upstream."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import php2shell_upstream as up  # noqa: E402

SOURCE = '''
class Exploit:
    def __init__(self):
        if profile == "bookworm":
            self.stage3_carrier = True
        else:
            self.stage3_carrier = False

    def forge(self):
        forge = bytearray(b"A" * 79)
        if 0x7F0000000000 <= v < 0x800000000000:
            pass
        if not (0x7F0000000000 <= p < 0x800000000000):
            pass

    def _connect(self):
        ctx = ssl.create_default_context()
        s = ctx.wrap_socket(s)
        return s


def parse_cookie(resp):
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", resp)
    if not m:
        return b""
    return urllib.parse.unquote_to_bytes(m.group(1).decode("latin1"))
'''


SOURCE_STAGE3 = """
class Exploit:
    def __init__(self):
        if profile == "bookworm":
            self.stage3_carrier = True
        else:
            self.stage3_carrier = False

    def stage3(self):
        parts = []
        parts += [self._file_part(), self._big_field()]
        if self.profile == "bookworm":
            pass
        else:
            for i in range(15):
                parts.append({"name": f"a{i:030d}"[:31], "data": ht})
            for i in range(2):
                parts.append({"name": f"f{i:02d}", "data": ref})
"""


class RuntimePatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        (self.repo / "exploit.py").write_text(SOURCE)

    def tearDown(self):
        self.tmp.cleanup()

    def test_patch_params(self):
        self.assertTrue(up.patch_params(str(self.repo)))
        text = (self.repo / "exploit.py").read_text()
        self.assertIn("P2S_STAGE1_N", text)
        self.assertIn("forge = bytearray(b\"A\" * self.stage1_forge_len)", text)
        self.assertIn("0x10000 < v", text)
        # idempotent
        self.assertFalse(up.patch_params(str(self.repo)))

    def test_patch_tls_keeps_sni(self):
        self.assertTrue(up.patch_tls(str(self.repo)))
        text = (self.repo / "exploit.py").read_text()
        self.assertIn("ssl._create_unverified_context()", text)
        self.assertIn("server_hostname=self.host", text)
        self.assertFalse(up.patch_tls(str(self.repo)))

    def test_patch_cookie_decode(self):
        self.assertTrue(up.patch_cookie_decode(str(self.repo)))
        text = (self.repo / "exploit.py").read_text()
        self.assertIn('raw = m.group(1).replace(b"+", b"%20")', text)
        self.assertIn("unquote_to_bytes(raw.decode", text)
        # idempotent
        self.assertFalse(up.patch_cookie_decode(str(self.repo)))
    def test_stage3_knobs_patch_real_anchors(self):
        import py_compile

        (self.repo / "exploit.py").write_text(SOURCE_STAGE3)
        self.assertTrue(up.patch_params(str(self.repo)))
        text = (self.repo / "exploit.py").read_text()
        for marker in ("P2S_STAGE3_PADS", "P2S_STAGE3_COOKIE",
                       "P2S_STAGE3_WFIELDS", "P2S_STAGE3_FAKE_LEN",
                       "P2S_STAGE3_FAKES", "P2S_STAGE3_B_NAME_LEN",
                       "for wi in range(getattr(self, '_p2s_wfields', 0) or 0)"):
            self.assertIn(marker, text)
        py_compile.compile(str(self.repo / "exploit.py"), doraise=True)
        # the second call must be a no-op
        self.assertFalse(up.patch_params(str(self.repo)))

    def test_missing_upstream_is_safe(self):
        self.assertFalse(up.patch_params(str(self.repo / "missing")))
        self.assertFalse(up.patch_tls(str(self.repo / "missing")))
        self.assertFalse(up.patch_cookie_decode(str(self.repo / "missing")))


if __name__ == "__main__":
    unittest.main()
