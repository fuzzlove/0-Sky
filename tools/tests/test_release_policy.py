import json
from pathlib import Path
import tempfile
import unittest

from tools import verify_release_policy as policy


class ReleasePolicyTests(unittest.TestCase):
    def fixture(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        tag = "v1.2.3"
        commit = "1" * 40
        digest = "2" * 64
        evidence = root / "release-evidence" / tag
        for relative in policy.REQUIRED_EVIDENCE:
            path = evidence / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        (evidence / "SHA256SUMS").write_text(
            f"{digest}  product.pkg\n", encoding="utf-8")
        (evidence / "build-manifest.json").write_text(json.dumps({
            "schema": 1, "mode": "distribution", "files": [{
                "path": "product.pkg", "role": "installer",
                "sha256": digest, "size": 123,
            }],
        }), encoding="utf-8")
        (evidence / "RELEASE_AUDIT.txt").write_text(
            "FAILURES: NONE\nFINAL_RESULT=PASS\n", encoding="utf-8")
        (evidence / "sbom/cyclonedx.json").write_text(json.dumps({
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [{"name": "fixture"}],
        }), encoding="utf-8")
        (evidence / "public-release-audit.json").write_text(json.dumps({
            "authoritative_release": tag,
            "releases": [{"tag": tag}, {"tag": "v1.2.2"}],
        }), encoding="utf-8")
        (root / "manifests").mkdir()
        (root / "manifests/release-status.json").write_text(json.dumps({
            "schema": 1,
            "current": {"tag": tag, "commit": commit,
                        "state": policy.CURRENT_STATE,
                        "installer": {"name": "product.pkg", "bytes": 123,
                                      "sha256": digest}},
            "deprecated": [{"tag": "v1.2.2", "commit": "3" * 40,
                            "state": policy.DEPRECATED_STATE}],
            "removed_from_distribution": [{"tag": "v1.2.2",
                "name": "old.pkg", "bytes": 100, "sha256": "4" * 64,
                "reason": "failed validation"}],
        }), encoding="utf-8")
        for relative in ("README.md", "INSTALL.md", "docs/RELEASE_POLICY.md",
                         "docs/RELEASE_CLEANUP_REPORT.md"):
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(tag + "\n", encoding="utf-8")
        return root

    def test_complete_policy_passes(self):
        self.assertEqual(policy.verify(self.fixture()), [])

    def test_current_cannot_be_deprecated(self):
        root = self.fixture()
        path = root / "manifests/release-status.json"
        value = json.loads(path.read_text())
        value["deprecated"][0]["tag"] = value["current"]["tag"]
        path.write_text(json.dumps(value))
        self.assertIn("RELEASE_STATE_NOT_UNIQUE", policy.verify(root))

    def test_installer_hash_must_match_evidence(self):
        root = self.fixture()
        path = root / "release-evidence/v1.2.3/SHA256SUMS"
        path.write_text(("5" * 64) + "  product.pkg\n")
        self.assertIn("CURRENT_CHECKSUM_MISMATCH", policy.verify(root))

    def test_required_evidence_is_fail_closed(self):
        root = self.fixture()
        (root / "release-evidence/v1.2.3/notarization-info.txt").unlink()
        self.assertIn("EVIDENCE_MISSING:notarization-info.txt", policy.verify(root))


if __name__ == "__main__":
    unittest.main()
