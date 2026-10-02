"""Regression tests for forensic comparison and deterministic converters."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))

from zero_sky_compat.archive_adapter import normalize_zip_compression
from zero_sky_compat.converter import plan
from zero_sky_compat.forensics import ArtifactRef, compare_pair
from zero_sky_compat.intake import extract_zip
from zero_sky_compat.rule_mining import mine


def zip_entry(name: str, data: bytes, mode: int = 0o100644,
              compression: int = zipfile.ZIP_DEFLATED) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, (2026, 1, 2, 3, 4, 6))
    info.create_system = 3
    info.external_attr = mode << 16
    info.compress_type = compression
    return info, data


def make_zip(path: Path, rows: list[tuple[zipfile.ZipInfo, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for info, data in rows:
            archive.writestr(info, data)


class ManualConversionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_safe_zip_relative_symlink_is_deferred_and_contained(self):
        archive = self.root / "safe.ipa"
        make_zip(archive, [zip_entry("Payload/A.app/file", b"ok"),
                           zip_entry("Payload/A.app/link", b"file", stat.S_IFLNK | 0o777)])
        output = self.root / "output"
        output.mkdir()
        extract_zip(archive, output)
        self.assertTrue((output / "Payload/A.app/link").is_symlink())
        self.assertEqual((output / "Payload/A.app/link").resolve().read_bytes(), b"ok")

    def test_zip_symlink_escape_is_rejected(self):
        archive = self.root / "escape.ipa"
        make_zip(archive, [zip_entry("Payload/A.app/link", b"../../../outside",
                                    stat.S_IFLNK | 0o777)])
        output = self.root / "output"
        output.mkdir()
        with self.assertRaisesRegex(ValueError, "unsafe archive path"):
            extract_zip(archive, output)
        self.assertFalse((self.root / "outside").exists())

    def test_compression_conversion_is_deterministic_and_preserves_original(self):
        source = self.root / "source.tipa"
        make_zip(source, [zip_entry("Payload/A.app/a", b"alpha", compression=zipfile.ZIP_LZMA),
                          zip_entry("Payload/A.app/b", b"beta", 0o100755, zipfile.ZIP_BZIP2)])
        original = source.read_bytes()
        first, second = self.root / "first.tipa", self.root / "second.tipa"
        one = normalize_zip_compression(source, first)
        two = normalize_zip_compression(source, second)
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertTrue(one["payload_bytes_preserved"] and two["payload_bytes_preserved"])
        with zipfile.ZipFile(first) as archive:
            self.assertEqual({item.compress_type for item in archive.infolist()}, {zipfile.ZIP_DEFLATED})
            self.assertEqual(archive.read("Payload/A.app/a"), b"alpha")

    def test_compression_converter_refuses_symbolic_source(self):
        real = self.root / "real.ipa"
        make_zip(real, [zip_entry("Payload/A.app/a", b"a", compression=zipfile.ZIP_LZMA)])
        linked = self.root / "linked.ipa"
        linked.symlink_to(real)
        with self.assertRaisesRegex(ValueError, "real artifact"):
            normalize_zip_compression(linked, self.root / "output.ipa")

    def test_dry_run_plan_never_creates_output(self):
        source = self.root / "source.ipa"
        make_zip(source, [zip_entry("Payload/A.app/a", b"a", compression=zipfile.ZIP_LZMA)])
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        value = plan(source, [])
        self.assertEqual(value["compatibility"], "LIKELY_CONVERTIBLE")
        self.assertEqual(value["device_changes"], "NONE")
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), before)
        self.assertEqual(list(self.root.iterdir()), [source])

    def test_dry_run_rejects_traversing_symlink_before_rule_match(self):
        source = self.root / "unsafe.ipa"
        make_zip(source, [zip_entry("Payload/A.app/link", b"../../../outside",
                                    stat.S_IFLNK | 0o777, zipfile.ZIP_LZMA)])
        value = plan(source, [])
        self.assertEqual(value["compatibility"], "UNSAFE_PACKAGE")
        self.assertEqual(value["transformations"], [])

    def test_forensic_comparison_uses_labels_and_records_recursive_diff(self):
        first, second = self.root / "first.ipa", self.root / "second.ipa"
        make_zip(first, [zip_entry("Payload/A.app/a", b"a")])
        make_zip(second, [zip_entry("Payload/A.app/a", b"b"),
                          zip_entry("Payload/A.app/new", b"n")])
        value = compare_pair("fixture", "test", ArtifactRef("before", first),
                             ArtifactRef("after", second))
        self.assertEqual(value["original"]["label"], "before")
        self.assertNotIn(str(self.root), json.dumps(value))
        self.assertEqual(value["diff"]["content_changed"], ["Payload/A.app/a"])
        self.assertEqual(value["diff"]["recursive_files"]["added"], ["Payload/A.app/new"])

    def test_rule_mining_requires_exact_preservation_for_zip_rule(self):
        source = self.root / "source.tipa"
        working = self.root / "working.tipa"
        make_zip(source, [zip_entry("a", b"same", compression=zipfile.ZIP_LZMA)])
        normalize_zip_compression(source, working)
        pair = compare_pair("compression", "deterministic_packaging_repair",
                            ArtifactRef("original", source), ArtifactRef("working", working))
        rules = mine([pair])
        self.assertEqual([rule["id"] for rule in rules], ["zip-compression-normalization-v1"])
        self.assertFalse(rules[0]["production_eligible"])


if __name__ == "__main__":
    unittest.main()
