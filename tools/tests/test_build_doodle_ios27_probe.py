from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch as mock_patch

from tools.build_doodle_ios27_probe import (PINNED_COMMIT,
                                            ensure_no_symlinks, validate_source)


class DoodlePrivateSourceProbeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        (self.source / ".git").mkdir(parents=True)
        self.patch = self.root / "port.patch"
        self.patch.write_bytes(b"reviewed patch fixture")
        self.theos = self.root / "theos"
        (self.theos / "makefiles").mkdir(parents=True)
        (self.theos / "makefiles" / "common.mk").write_text("fixture")

    def test_source_commit_and_patch_must_match_review(self):
        with mock_patch("tools.build_doodle_ios27_probe.checked_run",
                        side_effect=["0" * 40]):
            with self.assertRaisesRegex(ValueError, "reviewed 1.1 commit"):
                validate_source(self.source, self.patch, self.theos)
        with mock_patch("tools.build_doodle_ios27_probe.checked_run",
                        side_effect=[PINNED_COMMIT, ""]):
            with self.assertRaisesRegex(ValueError, "reviewed hash"):
                validate_source(self.source, self.patch, self.theos)

    def test_source_links_are_rejected(self):
        (self.source / "escape").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            ensure_no_symlinks(self.source)

if __name__ == "__main__":
    unittest.main()
