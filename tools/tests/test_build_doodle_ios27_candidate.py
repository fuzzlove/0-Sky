from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import build_doodle_ios27_candidate as candidate
from tools.build_doodle_ios27_probe import PINNED_COMMIT


class DoodleCandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        (self.source / '.git').mkdir(parents=True)
        self.theos = self.root / 'theos'
        (self.theos / 'makefiles').mkdir(parents=True)
        (self.theos / 'makefiles/common.mk').write_text('fixture')
        self.patch = self.root / 'port.patch'
        self.patch.write_text('unreviewed fixture')
        self.artifact = self.root / 'candidate.dylib'

    def test_rejects_unreviewed_patch_before_build(self):
        with patch.object(candidate, 'checked_run', side_effect=[PINNED_COMMIT, '']):
            with self.assertRaisesRegex(ValueError, 'not reviewed'):
                candidate.build(self.source, self.theos, self.patch, self.artifact)
        self.assertFalse(self.artifact.exists())

    def test_rejects_existing_artifact_before_build(self):
        self.artifact.write_bytes(b'prior evidence')
        with patch.object(candidate, 'checked_run', side_effect=[PINNED_COMMIT, '']), \
             patch.object(candidate, 'sha256', return_value=candidate.PATCH_SHA256):
            with self.assertRaises(FileExistsError):
                candidate.build(self.source, self.theos, self.patch, self.artifact)
        self.assertEqual(self.artifact.read_bytes(), b'prior evidence')

    def test_rejects_existing_report_before_build(self):
        report = self.root / 'prior.json'
        report.write_text('prior evidence')
        argv = ['candidate', '--source', str(self.source), '--theos', str(self.theos),
                '--artifact', str(self.artifact), '--report', str(report)]
        with patch.object(sys, 'argv', argv), patch.object(candidate, 'build') as build:
            with self.assertRaises(FileExistsError):
                candidate.main()
        build.assert_not_called()
        self.assertEqual(report.read_text(), 'prior evidence')


if __name__ == '__main__':
    unittest.main()
