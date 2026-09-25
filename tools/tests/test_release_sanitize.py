"""Release scan must inspect nested installers and honor local deny rules."""
from __future__ import annotations

import re
from pathlib import Path
import tempfile
import unittest
import zipfile

from tools.release_sanitize import audit, load_deny_patterns


class ReleaseSanitizeTests(unittest.TestCase):
    def test_nested_ipa_detects_hostname_without_disclosing_it(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / "Link.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Link.app/worker.py",
                                 "HOST='fixture-iphone.coredevice.local'\n")
            findings = audit([ipa])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["category"], "developer-coredevice-host")
            self.assertNotIn("fixture-iphone", str(findings))

    def test_custom_deny_and_clean_archive(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            deny = root / "deny.json"
            deny.write_text('{"patterns":{"vendor-id":"ACME_PRIVATE_ID"}}', encoding="utf-8")
            ipa = root / "Link.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Link.app/config.json", '{"id":"ACME_PRIVATE_ID"}')
            findings = audit([ipa], load_deny_patterns(deny))
            self.assertEqual(findings[0]["category"], "project-vendor-id")
            self.assertEqual(audit([ipa]), [])

    def test_binary_strings_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "helper"
            binary.write_bytes(b"\x00\x01/Users/" + b"privateuser/source\x00")
            self.assertEqual(audit([binary])[0]["category"], "fixed-home-path")

    def test_explicit_build_directory_is_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            release = Path(folder) / ".build/Release.app"
            release.mkdir(parents=True)
            (release / "leak.txt").write_text("/Users/" + "privateuser/source", encoding="utf-8")
            self.assertEqual(audit([release])[0]["category"], "fixed-home-path")


if __name__ == "__main__":
    unittest.main()
