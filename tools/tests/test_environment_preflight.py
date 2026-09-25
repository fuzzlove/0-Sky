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


if __name__ == "__main__":
    unittest.main()
