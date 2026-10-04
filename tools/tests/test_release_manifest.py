"""Regression coverage for the minimal public release allowlist."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools.release_manifest import (
    AUDIT_NAME,
    CHECKSUM_NAME,
    MANIFEST_NAME,
    ManifestError,
    generate,
    verify,
)


class ReleaseManifestTests(unittest.TestCase):
    PACKAGE = "0-Sky-Bridge-1.2.3-release-candidate-universal.pkg"

    def stage(self, root: Path) -> None:
        (root / self.PACKAGE).write_bytes(b"fixture package")
        (root / AUDIT_NAME).write_text(
            "Product: 0-Sky Bridge\nVersion: 1.2.3\nBuild: 42\n"
            "Build mode: release-candidate\nFINAL_RESULT=BLOCKED\n",
            encoding="utf-8",
        )

    def test_generate_and_verify_minimal_release(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.stage(root)
            manifest = generate(root, self.PACKAGE, product="0-Sky Bridge",
                                version="1.2.3", build="42",
                                mode="release-candidate")
            self.assertEqual(manifest["schema"], 1)
            self.assertEqual(
                {item.name for item in root.iterdir()},
                {self.PACKAGE, AUDIT_NAME, MANIFEST_NAME, CHECKSUM_NAME},
            )
            self.assertEqual(verify(root), manifest)

    def test_extra_release_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.stage(root)
            (root / "old-installer.pkg").write_bytes(b"stale")
            with self.assertRaisesRegex(ManifestError, "unexpected files"):
                generate(root, self.PACKAGE, product="0-Sky Bridge",
                         version="1.2.3", build="42", mode="release-candidate")

    def test_tamper_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.stage(root)
            generate(root, self.PACKAGE, product="0-Sky Bridge", version="1.2.3",
                     build="42", mode="release-candidate")
            (root / self.PACKAGE).write_bytes(b"changed")
            with self.assertRaisesRegex(ManifestError, "checksum mismatch"):
                verify(root)

    def test_candidate_cannot_publish_a_pass_report(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.stage(root)
            report = root / AUDIT_NAME
            report.write_text(report.read_text().replace("BLOCKED", "PASS"),
                              encoding="utf-8")
            with self.assertRaisesRegex(ManifestError, "artifact identity"):
                generate(root, self.PACKAGE, product="0-Sky Bridge",
                         version="1.2.3", build="42", mode="release-candidate")

    def test_symlinked_release_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root = base / "release"
            root.mkdir()
            target = base / "outside"
            target.write_bytes(b"fixture")
            (root / self.PACKAGE).symlink_to(target)
            (root / AUDIT_NAME).write_text(
                "Product: 0-Sky Bridge\nVersion: 1.2.3\nBuild: 42\n"
                "Build mode: release-candidate\nFINAL_RESULT=BLOCKED\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ManifestError, "missing or unsafe"):
                generate(root, self.PACKAGE, product="0-Sky Bridge",
                         version="1.2.3", build="42", mode="release-candidate")


if __name__ == "__main__":
    unittest.main()
