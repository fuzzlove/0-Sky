"""Versioned kit overrides remain manifest-valid and repeatable."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import prepare_release_kit as release
from tools.stage_verified_kit import digest
from tools.verify_prepared_kit import verify


class PrepareReleaseKitTests(unittest.TestCase):
    def test_overrides_are_manifest_bound_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source.py"
            source.write_text("print('portable')\n", encoding="utf-8")
            kit = root / "kit"
            target = kit / "host-mac/worker.py"
            target.parent.mkdir(parents=True)
            target.write_text("print('old')\n", encoding="utf-8")
            manifest = kit / "SHA256SUMS"
            manifest.write_text(f"{digest(target)}  ./host-mac/worker.py\n", encoding="utf-8")
            with patch.dict(release.OVERRIDES, {"host-mac/worker.py": source}, clear=True):
                release.apply_portability_overrides(kit)
                once = manifest.read_bytes()
                release.apply_portability_overrides(kit)
            self.assertEqual(manifest.read_bytes(), once)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertIn(digest(target), manifest.read_text(encoding="utf-8"))
            self.assertIn("./PORTABILITY.json", manifest.read_text(encoding="utf-8"))

    def test_unprepared_kit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            self.assertFalse(verify(Path(folder)))


if __name__ == "__main__":
    unittest.main()
