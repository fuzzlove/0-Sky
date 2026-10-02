"""The canonical Control payload is sealed from the one compiled app."""
from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import stage_control_payload


class StageControlPayloadTests(unittest.TestCase):
    def test_missing_theos_blocks_build(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            kit = Path(folder) / "kit"
            kit.mkdir()
            from unittest.mock import patch
            with patch.dict("os.environ", {"THEOS": ""}):
                with self.assertRaisesRegex(RuntimeError, "THEOS"):
                    stage_control_payload.stage(kit)

    @unittest.skipUnless(sys.platform == "darwin" and stage_control_payload.APP.is_dir(),
                         "requires a compiled Control app on macOS")
    def test_signed_source_payload_is_repeatable_and_manifest_bound(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            kit = Path(folder) / "kit"
            (kit / "packages").mkdir(parents=True)
            payload = kit / stage_control_payload.PAYLOAD_RELATIVE
            payload.write_bytes(b"previous verified slot")
            previous = hashlib.sha256(payload.read_bytes()).hexdigest()
            manifest = kit / "SHA256SUMS"
            manifest.write_text(f"{previous}  ./packages/Commissary-Universal.ipa\n")
            first = stage_control_payload.stage(kit, build=False)
            second = stage_control_payload.stage(kit, build=False)
            self.assertEqual(first, second)
            self.assertIn(first["sha256"], manifest.read_text())
            with tempfile.TemporaryDirectory() as extracted:
                subprocess.run(["/usr/bin/ditto", "-x", "-k", str(payload), extracted],
                               check=True, capture_output=True)
                app = Path(extracted) / "Payload/CrypStore.app"
                self.assertEqual(subprocess.run(["/usr/bin/codesign", "--verify",
                    "--deep", "--strict", str(app)], capture_output=True).returncode, 0)


if __name__ == "__main__":
    unittest.main()
