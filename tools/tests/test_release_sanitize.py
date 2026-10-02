"""Release scan must inspect nested installers and honor local deny rules."""
from __future__ import annotations

import re
import io
from pathlib import Path
import shutil
import tarfile
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

    def test_generic_file_url_is_not_personal_data(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "helper"
            binary.write_bytes(b"\x00file:///\x00file:///usr/share/resource\x00")
            self.assertEqual(audit([binary]), [])

    def test_temporary_file_url_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "helper"
            binary.write_bytes(b"\x00file:///private/tmp/build/output\x00")
            categories = {finding["category"] for finding in audit([binary])}
            self.assertIn("absolute-file-uri", categories)

    def test_explicit_build_directory_is_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            release = Path(folder) / ".build/Release.app"
            release.mkdir(parents=True)
            (release / "leak.txt").write_text("/Users/" + "privateuser/source", encoding="utf-8")
            self.assertEqual(audit([release])[0]["category"], "fixed-home-path")

    def test_native_binary_inside_ipa_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / "Link.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Link.app/Frameworks/helper.dylib",
                                 b"\x00/Users/" + b"privateuser/build\x00")
            self.assertEqual(audit([ipa])[0]["category"], "fixed-home-path")

    def test_native_extension_inside_wheel_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            wheel = Path(folder) / "sample-1.0-cp312-cp312-macosx_11_0_arm64.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("sample/native.so", b"\x00/Users/" + b"privateuser/build")
            self.assertEqual(audit([wheel])[0]["category"], "fixed-home-path")

    @unittest.skipUnless(shutil.which("bsdtar"),
                         "Debian archive tools unavailable")
    def test_compressed_debian_payload_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "debian-binary").write_text("2.0\n", encoding="ascii")
            for name, data in (("control.tar.gz", b"Package: fixture\n"),
                               ("data.tar.gz", b"/Users/" + b"privateuser/build")):
                with tarfile.open(root / name, "w:gz") as archive:
                    info = tarfile.TarInfo("./control" if name.startswith("control") else "./usr/bin/helper")
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            deb = root / "fixture.deb"
            with deb.open("wb") as stream:
                stream.write(b"!<arch>\n")
                for name in ("debian-binary", "control.tar.gz", "data.tar.gz"):
                    payload = (root / name).read_bytes()
                    header = ((name + "/").encode().ljust(16) + b"0".ljust(12) +
                              b"0".ljust(6) + b"0".ljust(6) + b"100644".ljust(8) +
                              str(len(payload)).encode().ljust(10) + b"`\n")
                    stream.write(header + payload)
                    if len(payload) % 2:
                        stream.write(b"\n")
            self.assertEqual(audit([deb])[0]["category"], "fixed-home-path")

    def test_large_binary_is_scanned_beyond_first_sample(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "large-helper"
            with binary.open("wb") as stream:
                stream.seek(65 * 1024 * 1024)
                stream.write(b"/Users/" + b"privateuser/build\x00")
            self.assertEqual(audit([binary])[0]["category"], "fixed-home-path")

    def test_sensitive_filename_is_reported_without_leaking_name(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "privateuser-secret.txt"
            path.write_text("clean", encoding="utf-8")
            deny = {"project-username": re.compile(b"privateuser")}
            findings = audit([path], deny)
            self.assertEqual(findings[0]["category"], "project-username")
            self.assertNotIn("privateuser", str(findings))


if __name__ == "__main__":
    unittest.main()
