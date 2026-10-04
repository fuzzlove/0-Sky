"""Host setup probes fail closed instead of hanging or printing tracebacks."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge"))
import macos_host_setup as setup  # noqa: E402


class MacSetupTimeoutTests(unittest.TestCase):
    def test_python_dependency_probe_timeout_is_a_failed_probe(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            requirements = Path(folder) / "requirements.txt"
            requirements.write_text("demo==1.0\n", encoding="utf-8")
            with mock.patch.object(setup, "REQUIREMENTS", requirements), \
                    mock.patch.object(
                        setup.subprocess, "run",
                        side_effect=subprocess.TimeoutExpired(["python"], 30)):
                self.assertEqual(setup.python_probe(Path(sys.executable)), (False, {}))

    def test_python_bootstrap_timeout_tries_candidates_then_blocks(self) -> None:
        with mock.patch.object(setup.shutil, "which", return_value=None), \
                mock.patch.object(
                    setup.subprocess, "run",
                    side_effect=subprocess.TimeoutExpired(["python"], 10)):
            self.assertIsNone(setup.bootstrap_python())

    def test_xcode_probe_timeout_is_not_accepted(self) -> None:
        with mock.patch.object(
                setup.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(["xcrun"], 20)):
            environment, sdk = setup.xcode_environment("macosx")
        self.assertIsNone(environment)
        self.assertEqual(sdk, "")


if __name__ == "__main__":
    unittest.main()
