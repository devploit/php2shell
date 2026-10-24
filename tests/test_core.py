#!/usr/bin/env python3
"""Unit tests for the non-exploit logic of the PHP2Shell toolkit."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import php2shell_auto as auto  # noqa: E402
import php2shell_calibrate as cal  # noqa: E402
import php2shell_paths as paths  # noqa: E402
import php2shell_ui as ui  # noqa: E402


class ClassificationTests(unittest.TestCase):
    def test_fixed_and_affected_versions(self):
        self.assertEqual(auto.classify("8.5.11"), ("8.5", 12, False))
        self.assertEqual(auto.classify("8.5.12"), ("8.5", 12, True))
        self.assertEqual(auto.classify("8.4.26"), ("8.4", 27, False))
        self.assertEqual(auto.classify("8.4.27"), ("8.4", 27, True))
        self.assertEqual(auto.classify("7.4.33"), ("7.4", None, None))
        self.assertIsNone(auto.classify("not-a-version"))

    def test_distro_normalization(self):
        self.assertEqual(auto.normalize_distro("bookworm"), "debian")
        self.assertEqual(auto.normalize_distro("Debian"), "debian")
        self.assertEqual(auto.normalize_distro("fedora"), "fedora")
        self.assertEqual(auto.normalize_distro("Alpine"), "alpine")
        self.assertEqual(auto.normalize_distro("ubuntu"), "ubuntu")
        self.assertIsNone(auto.normalize_distro("plan9"))


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.profiles = [
            {"name": "p-8426", "php_version": "8.4.26", "branch": "8.4"},
            {"name": "p-8425", "php_version": "8.4.25", "branch": "8.4"},
        ]

    def test_exact(self):
        profile, how = auto.select(self.profiles, "8.4.26", "8.4")
        self.assertEqual((profile["name"], how), ("p-8426", "exact"))

    def test_branch_only(self):
        profile, how = auto.select(self.profiles, "8.4.24", "8.4")
        self.assertEqual((profile["name"], how), ("p-8426", "branch-only"))

    def test_none(self):
        self.assertEqual(auto.select([], "8.4.26", "8.4"), (None, "none"))

    def test_auto_remote_connection_timeout_is_safe(self):
        with mock.patch.object(auto.socket, "create_connection", side_effect=socket.timeout):
            self.assertIsNone(auto.WorkerPins.auto_remote("http://127.0.0.1:1", max_pins=1))

    def test_container_arch_mapping(self):
        result = SimpleNamespace(returncode=0, stdout="x86_64\n", stderr="")
        with mock.patch.object(cal.subprocess, "run", return_value=result):
            self.assertEqual(cal.container_arch("x"), "amd64")

    def test_remote_arch_required(self):
        self.assertTrue(auto.remote_arch_required(True, None, None))
        self.assertFalse(auto.remote_arch_required(True, "amd64", None))
        self.assertFalse(auto.remote_arch_required(True, None, "p"))
        self.assertFalse(auto.remote_arch_required(False, None, None))

    def test_select_by_arch(self):
        profiles = [
            {"name": "p-arm", "php_version": "8.5.11", "branch": "8.5", "arch": "aarch64"},
            {"name": "p-amd", "php_version": "8.5.11", "branch": "8.5", "arch": "amd64"},
        ]
        profile, how = auto.select(profiles, "8.5.11", "8.5", "amd64")
        self.assertEqual((profile["name"], how), ("p-amd", "exact"))
        profile, how = auto.select(profiles, "8.5.11", "8.5", "aarch64")
        self.assertEqual((profile["name"], how), ("p-arm", "exact"))


class CommandTests(unittest.TestCase):
    def test_output_path(self):
        self.assertEqual(auto.output_path("id>p1"), "p1")
        self.assertEqual(auto.output_path("id>/out/p1"), "/out/p1")
        self.assertIsNone(auto.output_path("id"))

    def test_resolve_fetch_remote_relative(self):
        args = SimpleNamespace(no_fetch=False, fetch="", allow_remote=True)
        self.assertEqual(auto.resolve_fetch(args, "id>p1"), "/p1")

    def test_resolve_fetch_remote_absolute(self):
        args = SimpleNamespace(no_fetch=False, fetch="", allow_remote=True)
        self.assertEqual(auto.resolve_fetch(args, "id>/out/p1"), "")

    def test_resolve_fetch_local_and_overrides(self):
        local = SimpleNamespace(no_fetch=False, fetch="", allow_remote=False)
        self.assertEqual(auto.resolve_fetch(local, "id>p1"), "")
        explicit = SimpleNamespace(no_fetch=False, fetch="/proof", allow_remote=True)
        self.assertEqual(auto.resolve_fetch(explicit, "id>p1"), "/proof")
        disabled = SimpleNamespace(no_fetch=True, fetch="/proof", allow_remote=True)
        self.assertEqual(auto.resolve_fetch(disabled, "id>p1"), "")

    def test_stage_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            auto.stage_script(tmp, "id; uname -a")
            script = Path(tmp) / "c"
            text = script.read_text()
            self.assertIn("id; uname -a", text)
            self.assertIn("> /out/o 2>&1", text)
            self.assertEqual(script.stat().st_mode & 0o777, 0o755)


class ProofTests(unittest.TestCase):
    def test_explicit_proof(self):
        args = SimpleNamespace(proof_file="/x/p1", allow_remote=False,
                               container="c", repo_dir="/repo")
        self.assertEqual(auto.resolve_proof(args, ""), "/x/p1")

    def test_remote_has_no_local_proof(self):
        args = SimpleNamespace(proof_file=None, allow_remote=True,
                               container="c", repo_dir="/repo")
        self.assertEqual(auto.resolve_proof(args, "/p1"), "")

    def test_local_out_mount(self):
        args = SimpleNamespace(proof_file=None, allow_remote=False,
                               container="c", repo_dir="/repo")
        with mock.patch.object(auto, "container_out", return_value="/tmp/out"):
            self.assertEqual(auto.resolve_proof(args, ""), "/tmp/out/p1")

    def test_local_fallback_repo(self):
        args = SimpleNamespace(proof_file=None, allow_remote=False,
                               container="c", repo_dir="/repo")
        with mock.patch.object(auto, "container_out", return_value=None):
            self.assertEqual(auto.resolve_proof(args, ""), "/repo/out/p1")


class InventoryTests(unittest.TestCase):
    def test_profiles_are_valid(self):
        names = set()
        for path in sorted((ROOT / "profiles").glob("*.json")):
            if path.name in ("schema.json", "fpm-schema.json"):
                continue
            data = json.loads(path.read_text())
            self.assertIn("name", data, path)
            self.assertIn("php_version", data, path)
            self.assertIn("branch", data, path)
            self.assertIn(data.get("arch"), ("aarch64", "amd64"), path)
            self.assertIn("libphp", data, path)
            self.assertIn("stages", data, path)
            self.assertNotIn(data["name"], names, f"duplicate profile name: {path}")
            names.add(data["name"])
            if data.get("rce"):
                self.assertIsInstance(data.get("oom_mb"), int, path)
                if data.get("sapi") == "fpm":
                    # the FPM chain forges the stale var_hash directly; it
                    # does not use the Apache stage-3 htdata carrier
                    self.assertIsNotNone(data["fpm"].get("basic_globals"), path)
                    self.assertIsNotNone(data["fpm"].get("struct_size"), path)
                else:
                    self.assertIsNotNone(data["libphp"].get("htdata"), path)
                    self.assertTrue(data["stages"].get("stage3_pads"), path)

    def test_profile_schema_if_present(self):
        schema = ROOT / "profiles" / "schema.json"
        if schema.is_file():
            data = json.loads(schema.read_text())
            self.assertIn("$schema", data)
            self.assertEqual(data.get("type"), "object")
            self.assertIn("arch", data.get("required", []))

    def test_offset_arch_metadata(self):
        for path in sorted((ROOT / "profiles" / "offsets").glob("*.json")):
            data = json.loads(path.read_text())
            self.assertIn(data.get("arch"), ("aarch64", "amd64"), path)

    def test_catalog_structure(self):
        catalog = json.loads((ROOT / "catalog" / "vulnerable.json").read_text())
        branches = catalog.get("branches")
        self.assertIsInstance(branches, list)
        self.assertTrue(branches)
        for entry in branches:
            self.assertIn("branch", entry)

    def test_readme_local_links_exist(self):
        readme = (ROOT / "README.md").read_text()
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", readme):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            path = target.split("#", 1)[0]
            self.assertTrue((ROOT / path).exists(), f"missing README link: {target}")


class PathAndUiTests(unittest.TestCase):
    def test_default_repo_dir_env(self):
        with mock.patch.dict(os.environ, {"P2S_REPO_DIR": "/tmp/custom"}):
            self.assertEqual(paths.default_repo_dir(), "/tmp/custom")

    def test_default_repo_dir_returns_string(self):
        self.assertIsInstance(paths.default_repo_dir(), str)

    def test_worker_pins_from_socks(self):
        socks = [socket.socket(), socket.socket()]
        pins = auto.WorkerPins.from_socks(socks)
        self.assertEqual(len(pins.socks), 2)
        pins.close()

    def test_result_box_is_closed(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            ui.UI(color=False).result(False, "ARCH REQUIRED", "remote target without --arch/--profile")
        lines = [line for line in buffer.getvalue().splitlines() if line]
        self.assertTrue(lines)
        self.assertTrue(all(len(line) == 68 for line in lines), [len(line) for line in lines])
        self.assertTrue(lines[0].startswith("╭"))
        self.assertTrue(lines[-1].startswith("╰"))

    def test_prepare_lab_out_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out")
            paths.prepare_lab_out(path)
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o777)

    def test_banner_branding(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            ui.UI(color=False).banner()
        text = buffer.getvalue()
        self.assertIn("exploit by devploit", text)
        self.assertIn("authorized testing only", text)
        self.assertNotIn("framework v2", text)


if __name__ == "__main__":
    unittest.main()
