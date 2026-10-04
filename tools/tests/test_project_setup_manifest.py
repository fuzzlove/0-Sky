"""The device setup controller must accept only contained kit symlinks."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "bridge/0SkyBridge/Resources/Scripts/0sky_project_setup.py"
spec = importlib.util.spec_from_file_location("zero_sky_project_manifest_test", SOURCE)
project = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = project
spec.loader.exec_module(project)


class ProjectSetupManifestTests(unittest.TestCase):
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
