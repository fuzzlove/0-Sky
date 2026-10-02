"""Rollback selection must bind to the mounted generation, not a filename."""
import hashlib
from pathlib import Path
import tempfile
import unittest

import frida_cryptex_rollback_preflight as preflight


class RollbackSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def generation(self, name: str, manifest: bytes, complete: bool = True) -> Path:
        candidate = self.root / name
        candidate.mkdir()
        (candidate / preflight.REQUIRED[0]).write_bytes(manifest)
        if complete:
            for filename in preflight.REQUIRED[1:]:
                (candidate / filename).write_bytes(b"fixture")
        return candidate

    def test_exact_manifest_selects_complete_generation(self):
        selected = self.generation("prior", b"old")
        self.generation("new", b"new")
        digest = hashlib.sha256(b"old").hexdigest()
        self.assertEqual(preflight.select_generation(digest, self.root), selected)

    def test_incomplete_match_fails_closed(self):
        self.generation("prior", b"old", complete=False)
        with self.assertRaisesRegex(RuntimeError, "MATCHED_GENERATION_INCOMPLETE"):
            preflight.select_generation(hashlib.sha256(b"old").hexdigest(), self.root)

    def test_ambiguous_match_fails_closed(self):
        self.generation("prior-a", b"old")
        self.generation("prior-b", b"old")
        with self.assertRaisesRegex(RuntimeError, "AMBIGUOUS_OR_MISSING"):
            preflight.select_generation(hashlib.sha256(b"old").hexdigest(), self.root)

    def test_invalid_hash_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "INVALID_ACTIVE_MANIFEST_HASH"):
            preflight.select_generation("wrong", self.root)

    def test_sealed_record_requires_matching_bytes(self):
        path = self.root / "usr/sbin/frida-server"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"reviewed")
        record = {"frida": {"files": [{
            "path": "/var/jb/usr/sbin/frida-server",
            "sha256": hashlib.sha256(b"reviewed").hexdigest()}]}}
        preflight.verify_sealed_records(self.root, record)
        path.write_bytes(b"tampered")
        with self.assertRaisesRegex(RuntimeError, "HASH_MISMATCH"):
            preflight.verify_sealed_records(self.root, record)

    def test_sealed_record_rejects_traversal(self):
        record = {"preference_descriptors": [{
            "descriptor": "/var/jb/../private/secret.plist",
            "sha256": "0" * 64}]}
        with self.assertRaisesRegex(RuntimeError, "SEALED_RECORD_INVALID"):
            preflight.verify_sealed_records(self.root, record)


if __name__ == "__main__":
    unittest.main()
