from __future__ import annotations

import importlib.util
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[3]
HOST = ROOT / "bridge/HostTools"
sys.path.insert(0, str(HOST))
SPEC = importlib.util.spec_from_file_location(
    "bootstrap_payload_identity_test", HOST / "bootstrap_device.py")
bootstrap = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(bootstrap)


class BootstrapPayloadIdentityTests(unittest.TestCase):
    def make_ipa(self, path: Path, *, bundle: str = "com.liquidsky.CrypStore",
                 version: str = "9.8.7", build: str = "9.8.7.6") -> None:
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("Payload/CrypStore.app/Info.plist", plistlib.dumps({
                "CFBundleIdentifier": bundle,
                "CFBundleShortVersionString": version,
                "CFBundleVersion": build,
                "CFBundleExecutable": "CrypStore",
            }))
            archive.writestr("Payload/CrypStore.app/CrypStore", b"fixture")

    def test_version_gate_comes_from_exact_payload(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / "Control.ipa"
            self.make_ipa(ipa)
            self.assertEqual(
                bootstrap.ipa_identity(ipa, "com.liquidsky.CrypStore"),
                ("9.8.7", "9.8.7.6"),
            )

    def test_wrong_identity_and_traversal_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / "Control.ipa"
            self.make_ipa(ipa, bundle="com.example.wrong")
            with self.assertRaisesRegex(SystemExit, "identity mismatch"):
                bootstrap.ipa_identity(ipa, "com.liquidsky.CrypStore")
            with zipfile.ZipFile(ipa, "a") as archive:
                archive.writestr("../escape", b"no")
            with self.assertRaisesRegex(SystemExit, "unsafe or ambiguous"):
                bootstrap.ipa_identity(ipa, "com.example.wrong")


if __name__ == "__main__":
    unittest.main()
