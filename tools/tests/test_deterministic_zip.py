from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.deterministic_zip import build
from tools.rebuild_sha_manifest import rebuild


class DeterministicZipTests(unittest.TestCase):
    def test_stable_archive_preserves_relative_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            payload = root / "input/Payload/App.app"
            payload.mkdir(parents=True)
            (payload / "target").write_text("contents", encoding="utf-8")
            (payload / "alias").symlink_to("target")
            first, second = root / "first.ipa", root / "second.ipa"
            build(root / "input", first)
            os.utime(payload / "target", (1700000000, 1700000000))
            build(root / "input", second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.read("Payload/App.app/alias"), b"target")
                self.assertEqual(archive.namelist(), sorted(archive.namelist()))

    def test_external_symlink_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "input").mkdir()
            (root / "input/bad").symlink_to("/tmp/other")
            with self.assertRaisesRegex(ValueError, "unsafe symlink"):
                build(root / "input", root / "bad.zip")

    def test_hash_manifest_includes_relative_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "target").write_text("fixture", encoding="utf-8")
            (root / "alias").symlink_to("target")
            self.assertEqual(rebuild(root), 2)
            manifest = (root / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn("  ./alias\n", manifest)
            (root / "external").symlink_to("/tmp/other")
            with self.assertRaisesRegex(ValueError, "unresolved|escapes|unsafe"):
                rebuild(root)
