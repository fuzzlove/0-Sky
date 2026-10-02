import json
from pathlib import Path
import tempfile
import unittest

from tools.export_toolkit_uat import export, load_receipt


def receipt(reference: str) -> dict:
    return {
        "device": {"device_reference": reference, "product": "test-phone",
                   "version": "27.0", "build": "TEST", "usb_identity_verified": True},
        "collected_at": 1,
        "verified_overall": "FAIL",
        "result": {
            "overall": "DEGRADED",
            "smoke": {"result": "FAIL", "counts": {"FAIL": 1},
                      "tests": [{"id": "SMOKE-01", "result": "FAIL", "expected": "healthy",
                                 "observed": "unverified", "evidence": [], "remediation": "review"}]},
            "uat": {"result": "SKIP", "counts": {"SKIP": 1},
                    "tests": [{"id": "UAT-001", "result": "SKIP", "expected": "screen",
                               "observed": "not run", "evidence": []}]},
        },
        "inventory": {"environment": {"ios_version": "27.0", "bootstrap": "rootless"},
                      "components": [{"id": "filza", "name": "Filza", "type": "APP",
                                      "category": "Apps/Security Research", "badge": "INSTALLED",
                                      "facets": {"installation": "INSTALLED",
                                                 "compatibility": "UNVERIFIED",
                                                 "dependencies": "PASS"}}]},
    }


class ToolkitUATExportTests(unittest.TestCase):
    def test_exports_all_cases_and_never_accepts_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / "first.json", root / "second.json"]
            for path, reference in zip(paths, ("a" * 16, "b" * 16)):
                path.write_text(json.dumps(receipt(reference)))
            output = root / "bundle"
            summary = export(paths, output)
            self.assertEqual(summary["overall"], "FAIL")
            self.assertFalse(summary["release_accepted"])
            self.assertEqual(len(json.loads((output / "apps.json").read_text())), 2)
            self.assertEqual(len(json.loads((output / "smoke-tests.json").read_text())), 2)
            self.assertEqual(len(json.loads((output / "uat-results.json").read_text())), 2)
            self.assertEqual(len(json.loads((output / "failures.json").read_text())), 2)
            with self.assertRaisesRegex(ValueError, "new output"):
                export(paths, output)

    def test_rejects_duplicate_device_and_wrong_combined_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "one.json", root / "two.json"
            first.write_text(json.dumps(receipt("a" * 16)))
            second.write_text(json.dumps(receipt("a" * 16)))
            with self.assertRaisesRegex(ValueError, "same device"):
                export([first, second], root / "duplicate")
            wrong = receipt("b" * 16)
            wrong["verified_overall"] = "PASS"
            second.write_text(json.dumps(wrong))
            with self.assertRaisesRegex(ValueError, "differs"):
                load_receipt(second)

    def test_sensitive_component_text_fails_before_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = receipt("a" * 16)
            value["inventory"]["components"][0]["name"] = "/Users/tester/private"
            source = root / "device.json"
            source.write_text(json.dumps(value))
            target = root / "bundle"
            with self.assertRaisesRegex(ValueError, "sensitive data"):
                export([source], target)
            self.assertFalse(target.exists())


if __name__ == "__main__":
    unittest.main()
