from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from tools import verify_eula


class VerifyEULATests(unittest.TestCase):
    def test_canonical_is_valid(self) -> None:
        result = verify_eula.verify(verify_eula.LEGAL)
        self.assertEqual(result["eula_version"], "1.0")

    def test_text_change_requires_metadata_digest_update(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ("EULA.md", "EULA.json"):
                (root / name).write_bytes((verify_eula.LEGAL / name).read_bytes())
            (root / "EULA.md").write_bytes((root / "EULA.md").read_bytes() + b"\n")
            with self.assertRaises(verify_eula.EULAError):
                verify_eula.verify(root)

    def test_version_change_requires_document_header_update(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for name in ("EULA.md", "EULA.json"):
                (root / name).write_bytes((verify_eula.LEGAL / name).read_bytes())
            metadata = json.loads((root / "EULA.json").read_text(encoding="utf-8"))
            metadata["eula_version"] = "2.0"
            (root / "EULA.json").write_text(json.dumps(metadata), encoding="utf-8")
            with self.assertRaises(verify_eula.EULAError):
                verify_eula.verify(root)

    def test_bundled_files_match_canonical_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "Bridge.app"
            legal = app / "Contents/Resources/Legal"
            legal.mkdir(parents=True)
            for name in ("EULA.md", "EULA.json"):
                (legal / name).write_bytes((verify_eula.LEGAL / name).read_bytes())
            self.assertEqual(verify_eula.verify(legal), verify_eula.verify(verify_eula.LEGAL))
            self.assertEqual((legal / "EULA.md").read_bytes(),
                             (verify_eula.LEGAL / "EULA.md").read_bytes())


if __name__ == "__main__":
    unittest.main()
