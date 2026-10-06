"""Portable, read-only preflight behavior without a connected device."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import environment_preflight as preflight


class EnvironmentPreflightTests(unittest.TestCase):
    def test_architecture_and_rosetta(self) -> None:
        self.assertEqual(preflight.architecture("arm64")["native"], "arm64")
        translated = preflight.architecture("x86_64", True)
        self.assertEqual(translated["native"], "arm64")
        self.assertTrue(translated["rosetta"])
        self.assertEqual(preflight.architecture("mips")["status"], "BLOCKED")
        self.assertEqual(preflight.safe_tool_path(str(Path.home() / "bin/tool")), "~/bin/tool")

    def test_required_and_optional_tools(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(preflight.resolve_tool("missing", required=True,
                            search_path=empty)["status"], "FAIL")
            self.assertEqual(preflight.resolve_tool("missing", required=False,
                            search_path=empty)["status"], "DEGRADED")

    def test_incompatible_tool_is_not_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            tool = Path(folder) / "python3.12"
            tool.write_text("#!/bin/sh\necho Python 3.11.9\n", encoding="utf-8")
            tool.chmod(0o755)
            result = preflight.resolve_tool("python3.12", required=True,
                                            search_path=folder,
                                            required_prefix="Python 3.12.")
            self.assertEqual(result["status"], "FAIL")

    def test_another_device_must_be_selected_exactly(self) -> None:
        with patch.object(preflight, "command", return_value=(0, "")):
            self.assertEqual(preflight.inspect_device("fixture-other-device-00000001", None)["status"],
                             "BLOCKED")

    def test_missing_external_kit_blocks_full_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            result = preflight.report(mode="development", kit=Path(folder) / "missing-kit",
                                      discover_device=False)
            self.assertEqual(result["kit"]["status"], "BLOCKED")
            self.assertEqual(result["status"], "BLOCKED")

    def test_missing_theos_prints_complete_install_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            result = preflight.report(mode="development", kit=Path(folder) / "missing-kit",
                                      environment={}, discover_device=False)
        self.assertEqual(result["theos"]["status"], "BLOCKED")
        action = result["theos"]["remediation"]
        self.assertIn("git clone --recursive", action)
        self.assertIn("dd5c14bb9d91311e221d51b5bfb8c9e5948156db", action)
        self.assertIn("submodule update --init --recursive", action)

    def test_human_report_prints_exact_repair_command(self) -> None:
        value = {"status": "BLOCKED", "toolchain": [{"tool": "xcodebuild",
                 "status": "FAIL", "remediation":
                 "sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"}],
                 "kit": {"status": "PASS"}, "host_runtime": {"status": "REPAIRABLE",
                 "remediation": "python3 tools/build_host_runtime.py KIT"},
                 "theos": {"status": "BLOCKED", "remediation": "git clone --recursive URL"}}
        rendered = preflight.human_report(value)
        self.assertIn("Required action:", rendered)
        self.assertIn("sudo xcode-select", rendered)
        self.assertIn("python3 tools/build_host_runtime.py", rendered)
        self.assertIn("git clone --recursive", rendered)

    @patch.object(preflight, "discover_signing_identities", return_value=[])
    def test_release_signing_lists_each_missing_requirement(self, _discover) -> None:
        with tempfile.TemporaryDirectory() as folder:
            result = preflight.report(mode="release", kit=Path(folder) / "missing-kit",
                                      environment={}, discover_device=False)
        security = result["security"]
        self.assertEqual(security["status"], "BLOCKED")
        self.assertIn("Developer ID Application", security["detail"])
        self.assertIn("Developer ID Installer", security["detail"])
        self.assertIn("notarytool", security["remediation"])

    @patch.object(preflight, "validate_notary_profile", return_value=True)
    @patch.object(preflight, "discover_signing_identities")
    def test_release_signing_accepts_one_identity_of_each_type(self, discover, _notary) -> None:
        from tools.signing_identities import Identity
        discover.return_value = [Identity("A" * 40, "Developer ID Application"),
                                 Identity("B" * 40, "Developer ID Installer")]
        with tempfile.TemporaryDirectory() as folder:
            result = preflight.report(mode="release", kit=Path(folder) / "missing-kit",
                                      notary_profile="release-profile", environment={},
                                      discover_device=False)
        self.assertEqual(result["security"]["status"], "PASS")

    @patch.object(preflight, "validate_notary_profile", return_value=False)
    @patch.object(preflight, "discover_signing_identities")
    def test_release_signing_rejects_invalid_notary_profile(self, discover, _notary) -> None:
        from tools.signing_identities import Identity
        discover.return_value = [Identity("A" * 40, "Developer ID Application"),
                                 Identity("B" * 40, "Developer ID Installer")]
        with tempfile.TemporaryDirectory() as folder:
            result = preflight.report(mode="release", kit=Path(folder) / "missing-kit",
                                      notary_profile="invalid-profile", environment={},
                                      discover_device=False)
        self.assertEqual(result["security"]["status"], "BLOCKED")
        self.assertEqual(result["security"]["notary_profile"], "invalid")
        self.assertIn("did not authenticate", result["security"]["remediation"])


if __name__ == "__main__":
    unittest.main()
