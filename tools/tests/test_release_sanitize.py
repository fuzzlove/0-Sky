"""Release scan must inspect nested installers and honor local deny rules."""
from __future__ import annotations

import re
import io
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools.release_sanitize import audit, blocking_findings, load_deny_patterns


class ReleaseSanitizeTests(unittest.TestCase):
    def test_default_cli_summarizes_advisories_and_verbose_lists_them(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            payload = Path(folder) / "payload.txt"
            payload.write_text("/Users/public-builder/source", encoding="utf-8")
            command = [sys.executable, str(Path(__file__).resolve().parents[1]
                       / "release_sanitize.py"), str(payload)]
            concise = subprocess.run(command, capture_output=True, text=True, check=True)
            self.assertIn('"advisory_summary"', concise.stdout)
            self.assertNotIn('"advisory_findings"', concise.stdout)
            verbose = subprocess.run(command + ["--verbose"], capture_output=True,
                                     text=True, check=True)
            self.assertIn('"advisory_findings"', verbose.stdout)

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

    def test_exact_builder_path_is_advisory_but_hostname_remains_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            deny = root / "deny.json"
            deny.write_text('{"patterns":{"builder-home":"/Users/releaseowner",'
                            '"hostname":"private-builder-name"}}', encoding="utf-8")
            payload = root / "payload"
            payload.write_text("/Users/releaseowner/src private-builder-name")
            findings = audit([payload], load_deny_patterns(deny))
            blocked = {item["category"] for item in blocking_findings(findings)}
            self.assertNotIn("project-build-reference-builder-home", blocked)
            self.assertIn("project-hostname", blocked)

    def test_binary_strings_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "helper"
            binary.write_bytes(b"\x00\x01/Users/" + b"privateuser/source\x00")
            self.assertEqual(audit([binary])[0]["category"], "fixed-home-path")
            self.assertEqual(blocking_findings(audit([binary])), [])

    def test_parser_source_header_is_not_a_bundled_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "parser.py"
            source.write_text('HEADER = "-----BEGIN PRIVATE KEY-----"\n')
            self.assertEqual(audit([source]), [])

    def test_complete_private_key_material_remains_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            key = Path(folder) / "private.key"
            key.write_bytes(b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 64 + b"\n")
            findings = audit([key])
            self.assertEqual(findings[0]["category"], "private-key")
            self.assertEqual(blocking_findings(findings), findings)

    def test_public_test_key_exception_requires_exact_archive_hash_and_member(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            wheel = Path(folder) / "fixture.whl"
            key = b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 64 + b"\n"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("Crypto/SelfTest/public.pem", key)
            exception = [{
                "file": "fixture.whl", "category": "private-key",
                "member_prefix": "Crypto/SelfTest/",
                "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                "reason": "public fixture",
            }]
            findings = audit([wheel], exceptions=exception)
            self.assertEqual(blocking_findings(findings), [])
            self.assertEqual(findings[0]["disposition"], "verified-public-test-fixture")
            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr("changed", "bytes")
            self.assertNotEqual(blocking_findings(audit([wheel], exceptions=exception)), [])

    def test_public_test_key_member_hash_survives_safe_wheel_repack(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            wheel = Path(folder) / "fixture.whl"
            key = b"-----BEGIN PRIVATE KEY-----\n" + b"A" * 64 + b"\n"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("Crypto/SelfTest/public.py", key)
            exception = [{
                "file": "fixture.whl", "category": "private-key",
                "member_prefix": "Crypto/SelfTest/public.py",
                "member_sha256": hashlib.sha256(key).hexdigest(),
                "reason": "exact public fixture",
            }]
            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr("signed-native.so", b"different outer archive bytes")
            findings = audit([wheel], exceptions=exception)
            self.assertEqual(blocking_findings(findings), [])
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("Crypto/SelfTest/public.py", key + b"changed")
            self.assertNotEqual(blocking_findings(audit([wheel], exceptions=exception)), [])

    def test_hash_bound_network_test_fixture_can_match_dynamic_deny_category(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            wheel = Path(folder) / "fixture.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("tests/network.py", "HOST = '192.168.55.44'")
            exception = [{
                "file": "fixture.whl", "category": "project-local-address-*",
                "member_prefix": "tests/",
                "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
                "reason": "public fixture",
            }]
            deny = {"project-local-address-7": re.compile(rb"192\.168\.55\.44")}
            findings = audit([wheel], deny, exceptions=exception)
            self.assertEqual(blocking_findings(findings), [])

    def test_exact_project_deny_remains_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / "helper"
            binary.write_bytes(b"/Users/releaseowner/source")
            findings = audit([binary], {"project-release-user": re.compile(b"releaseowner")})
            self.assertIn("project-release-user", {item["category"] for item in findings})
            self.assertIn("project-release-user",
                          {item["category"] for item in blocking_findings(findings)})

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
                    info = tarfile.TarInfo("./control" if name.startswith("control") else "./var/jb/usr/bin/helper")
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
                    if name.startswith("data"):
                        link = tarfile.TarInfo("./var/jb/usr/bin/helper-link")
                        link.type = tarfile.SYMTYPE
                        link.linkname = "/var/jb/usr/bin/helper"
                        archive.addfile(link)
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
            self.assertNotIn("unsafe-symlink", {item["category"] for item in audit([deb])})
            original_open = tarfile.open
            def unsupported_read(name, mode="r", *args, **kwargs):
                if mode == "r:*":
                    raise tarfile.ReadError("unsupported compression")
                return original_open(name, mode, *args, **kwargs)
            with patch("tools.release_sanitize.tarfile.open", side_effect=unsupported_read):
                fallback = audit([deb])
            self.assertEqual(fallback[0]["category"], "fixed-home-path")
            self.assertNotIn("invalid-archive", {item["category"] for item in fallback})

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
