import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools import pii_audit


class PIIAuditAllowlistTests(unittest.TestCase):
    def make_root(self, payload: bytes, *, digest: str | None = None) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        fixture = root / "vendor/fixture.bin"
        fixture.parent.mkdir(parents=True)
        fixture.write_bytes(payload)
        allowlist = root / pii_audit.ALLOWLIST_PATH
        allowlist.parent.mkdir(parents=True)
        allowlist.write_text(json.dumps({
            "schema": 1,
            "entries": [{
                "file": "vendor/fixture.bin",
                "category": "unexpected-binary",
                "sha256": digest or hashlib.sha256(payload).hexdigest(),
                "reason": "test fixture",
            }],
        }))
        return root

    def test_exact_category_path_and_hash_is_approved(self):
        root = self.make_root(b"fixture")
        findings, count = pii_audit.apply_allowlist(root, [{
            "file": "vendor/fixture.bin", "category": "unexpected-binary"}])
        self.assertEqual(findings, [])
        self.assertEqual(count, 1)

    def test_changed_bytes_fail_closed(self):
        root = self.make_root(b"changed", digest=hashlib.sha256(b"original").hexdigest())
        findings, count = pii_audit.apply_allowlist(root, [{
            "file": "vendor/fixture.bin", "category": "unexpected-binary"}])
        self.assertEqual(count, 0)
        self.assertEqual(findings, [{
            "category": "allowlist-hash-mismatch", "file": "vendor/fixture.bin"}])

    def test_stale_category_does_not_hide_a_new_finding(self):
        root = self.make_root(b"fixture")
        findings, count = pii_audit.apply_allowlist(root, [{
            "file": "vendor/fixture.bin", "category": "private-key"}])
        self.assertEqual(count, 0)
        self.assertIn({"file": "vendor/fixture.bin", "category": "private-key"}, findings)
        self.assertIn({"file": "vendor/fixture.bin", "category": "allowlist-stale"}, findings)


if __name__ == "__main__":
    unittest.main()
