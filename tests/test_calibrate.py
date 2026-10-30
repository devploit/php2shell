#!/usr/bin/env python3
"""Tests for the stage-3 pads/carrier calibration helpers."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import php2shell_calibrate as cal  # noqa: E402


class PadSpecTests(unittest.TestCase):
    def test_builtins_are_preserved(self):
        self.assertEqual(cal.parse_pads(None), None)
        self.assertEqual(cal.parse_pads("bookworm"), "bookworm")
        self.assertEqual(cal.parse_pads("lab"), "lab")

    def test_explicit_spec_with_repetition(self):
        self.assertEqual(cal.parse_pads("4:4x5,31:31x6"),
                         [(4, 4)] * 5 + [(31, 31)] * 6)

    def test_explicit_spec_without_repetition(self):
        self.assertEqual(cal.parse_pads("4:4,31:31"),
                         [(4, 4), (31, 31)])

    def test_bad_spec_is_rejected(self):
        with self.assertRaises(SystemExit):
            cal.parse_pads("4:4x")


class CarrierSelectionTests(unittest.TestCase):
    def test_builtin_bookworm_is_carrier(self):
        self.assertTrue(cal.stage3_carrier_for("bookworm", "auto"))

    def test_lab_is_not_carrier(self):
        self.assertFalse(cal.stage3_carrier_for("lab", "auto"))

    def test_explicit_pads_default_to_lab_branch(self):
        self.assertFalse(cal.stage3_carrier_for([(4, 4)], "auto"))

    def test_override_wins(self):
        self.assertTrue(cal.stage3_carrier_for([(4, 4)], "carrier"))
        self.assertFalse(cal.stage3_carrier_for("bookworm", "lab"))


class ProfileJsonTests(unittest.TestCase):
    def test_uncalibrated(self):
        self.assertEqual(cal.stage3_profile_json(None), (None, None))

    def test_lab(self):
        pads, carrier = cal.stage3_profile_json({"pads": "lab"})
        self.assertEqual(carrier, False)
        self.assertEqual(pads[0], [8, 7])

    def test_explicit_pads_keep_the_measured_branch(self):
        pads, carrier = cal.stage3_profile_json(
            {"pads": [(4, 4), (31, 31)], "carrier": False})
        self.assertEqual(pads, [[4, 4], [31, 31]])
        self.assertFalse(carrier)

    def test_bookworm(self):
        pads, carrier = cal.stage3_profile_json({"pads": "bookworm"})
        self.assertEqual(pads, [[31, 31]] * 6)
        self.assertTrue(carrier)


class Deb13ProfileTests(unittest.TestCase):
    def test_profile_matches_the_runtime_branch(self):
        profile = json.loads(
            (ROOT / "profiles" / "php-8.4.26-deb13-apxs2-amd64.json").read_text())
        stages = profile["stages"]
        self.assertEqual(profile["upstream_profile"], "lab")
        self.assertFalse(stages["stage3_carrier"])
        self.assertEqual(stages["stage3_fake_len"], 31)
        self.assertEqual(stages["stage3_fakes"], 12)
        self.assertEqual(stages["stage3_b_name_len"], 3)


if __name__ == "__main__":
    unittest.main()
