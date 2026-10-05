"""The device setup controller must accept only contained kit symlinks."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "bridge/0SkyBridge/Resources/Scripts/0sky_project_setup.py"
spec = importlib.util.spec_from_file_location("zero_sky_project_manifest_test", SOURCE)
project = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = project
spec.loader.exec_module(project)


class ProjectSetupManifestTests(unittest.TestCase):
    def test_bundled_ipa_identity_uses_payload_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / "Control.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/CrypStore.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "com.liquidsky.CrypStore",
                    "CFBundleShortVersionString": "3.5.37",
                    "CFBundleVersion": "3.5.37.0",
                }))
            self.assertEqual(project.bundled_ipa_identity(
                ipa, "com.liquidsky.CrypStore"), {
                    "bundle_id": "com.liquidsky.CrypStore",
                    "version": "3.5.37",
                    "build": "3.5.37.0",
                })

    def test_bundled_ipa_identity_rejects_wrong_id_and_traversal(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            wrong = root / "wrong.ipa"
            with zipfile.ZipFile(wrong, "w") as archive:
                archive.writestr("Payload/Control.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "com.example.Wrong",
                    "CFBundleShortVersionString": "1.0",
                    "CFBundleVersion": "1",
                }))
            with self.assertRaises(project.PoCError):
                project.bundled_ipa_identity(wrong, "com.liquidsky.CrypStore")

            traversing = root / "traversing.ipa"
            with zipfile.ZipFile(traversing, "w") as archive:
                archive.writestr("../outside", b"unsafe")
                archive.writestr("Payload/Control.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "com.liquidsky.CrypStore",
                    "CFBundleShortVersionString": "3.5.37",
                    "CFBundleVersion": "3.5.37.0",
                }))
            with self.assertRaises(project.PoCError):
                project.bundled_ipa_identity(traversing, "com.liquidsky.CrypStore")

    def test_contained_relative_runtime_symlink_is_accepted(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "python/bin/2to3-3.12"
            target.parent.mkdir(parents=True)
            target.write_text("entry point")
            link = target.with_name("2to3")
            link.symlink_to(target.name)
            self.assertTrue(project.safe_manifest_entry(root, link))
            self.assertEqual(project.sha256(link), project.sha256(target))

    def test_traversing_or_absolute_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            root = parent / "kit"
            root.mkdir()
            outside = parent / "outside"
            outside.write_text("not in kit")
            traversing = root / "traversing"
            traversing.symlink_to("../outside")
            absolute = root / "absolute"
            absolute.symlink_to(outside)
            self.assertFalse(project.safe_manifest_entry(root, traversing))
            self.assertFalse(project.safe_manifest_entry(root, absolute))

    def test_broken_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            link = root / "missing"
            link.symlink_to("absent")
            self.assertFalse(project.safe_manifest_entry(root, link))


if __name__ == "__main__":
    unittest.main()
