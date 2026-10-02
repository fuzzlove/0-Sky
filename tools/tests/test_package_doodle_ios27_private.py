import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest.mock import patch

from tools import package_doodle_ios27_private as private


class PrivateDoodlePackageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        (self.source / '.git').mkdir(parents=True)
        self.patch = self.root / 'port.patch'
        self.patch.write_text('fixture')
        self.candidate = self.root / 'Doodle.dylib'
        self.candidate.write_bytes(b'candidate')
        self.report = self.root / 'build.json'
        self.report.write_text(json.dumps({
            'component': private.PACKAGE,
            'source_commit': private.PINNED_COMMIT,
            'patch_sha256': private.PATCH_SHA256,
            'candidate_sha256': private.sha256(self.candidate),
            'host_signature': 'PASS', 'reproducible': True,
        }))

    def test_rejects_prior_package_without_build(self):
        output = self.root / 'prior.deb'
        output.write_bytes(b'previous evidence')
        with self.assertRaises(FileExistsError):
            private.package(self.source, self.patch, self.candidate,
                            self.report, output)
        self.assertEqual(output.read_bytes(), b'previous evidence')

    def test_filter_is_valid_xml_plist_and_only_targets_springboard(self):
        self.patch.write_text('{ Filter = { Bundles = ("com.apple.springboard"); }; }')
        value = plistlib.loads(private.canonical_filter(self.patch))
        self.assertEqual(value, {'Filter': {'Bundles': ['com.apple.springboard']}})
        self.patch.write_text('{ Filter = { Bundles = ("com.apple.other"); }; }')
        with self.assertRaises(ValueError):
            private.canonical_filter(self.patch)

    def test_rejects_mismatched_signed_candidate(self):
        output = self.root / 'new.deb'
        self.candidate.write_bytes(b'changed candidate')
        with patch.object(private, 'checked_run', side_effect=[private.PINNED_COMMIT, '']), \
             patch.object(private, 'sha256', side_effect=lambda path:
                private.PATCH_SHA256 if path == self.patch else 'changed-hash'):
            with self.assertRaisesRegex(ValueError, 'do not match'):
                private.package(self.source, self.patch, self.candidate,
                                self.report, output)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
