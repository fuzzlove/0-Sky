"""Nested wheel signing preserves a valid, reproducible wheel inventory."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

from tools.sign_release_kit import sign_kit, sign_wheel


class SignReleaseKitTests(unittest.TestCase):
    def test_signed_wheel_record_is_rehashed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            wheel = Path(folder) / "demo-1.0-cp312-cp312-macosx_11_0_arm64.whl"
            record_name = "demo-1.0.dist-info/RECORD"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("demo/native.so", b"native")
                archive.writestr("demo/__init__.py", b"")
                archive.writestr(record_name,
                                 "demo/native.so,,\ndemo/__init__.py,,\n" +
                                 record_name + ",,\n")
            def fake_sign(path: Path, identity: str) -> None:
                path.write_bytes(path.read_bytes() + b"-signed")
            with (patch("tools.sign_release_kit.is_macho",
                        side_effect=lambda path: path.name == "native.so"),
                  patch("tools.sign_release_kit.platform_of", return_value="MACOS"),
                  patch("tools.sign_release_kit.sign", side_effect=fake_sign)):
                self.assertEqual(sign_wheel(wheel, "fingerprint"), 1)
            with zipfile.ZipFile(wheel) as archive:
                native = archive.read("demo/native.so")
                rows = {row[0]: row for row in csv.reader(io.StringIO(
                    archive.read(record_name).decode("utf-8")))}
            encoded = base64.urlsafe_b64encode(hashlib.sha256(native).digest()).rstrip(b"=").decode()
            self.assertEqual(rows["demo/native.so"][1], "sha256=" + encoded)
            self.assertEqual(rows["demo/native.so"][2], str(len(native)))
            self.assertEqual(rows[record_name][1:], ["", ""])

    def test_wheel_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            wheel = Path(folder) / "bad.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("../native.so", b"native")
                archive.writestr("demo-1.0.dist-info/RECORD",
                                 "../native.so,,\ndemo-1.0.dist-info/RECORD,,\n")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                sign_wheel(wheel, "fingerprint")

    def test_duplicate_wheel_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            wheel = Path(folder) / "bad.whl"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(wheel, "w") as archive:
                    archive.writestr("demo/native.so", b"first")
                    archive.writestr("demo/native.so", b"second")
                    archive.writestr("demo-1.0.dist-info/RECORD",
                                     "demo/native.so,,\n"
                                     "demo-1.0.dist-info/RECORD,,\n")
            with self.assertRaisesRegex(ValueError, "duplicate"):
                sign_wheel(wheel, "fingerprint")

    def test_runtime_manifest_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            kit = root / "kit"
            (kit / "host-mac/wheelhouse").mkdir(parents=True)
            (root / "outside").write_bytes(b"not release content")
            manifest = {
                "components": [{"path": "../outside", "payloads": {}}]
            }
            (kit / "host-mac/HOST_RUNTIME_MANIFEST.json").write_text(
                json.dumps(manifest), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                sign_kit(kit, "fingerprint")


if __name__ == "__main__":
    unittest.main()
