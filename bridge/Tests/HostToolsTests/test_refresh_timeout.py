from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


HOST_TOOLS = Path(__file__).resolve().parents[2] / "HostTools"
sys.path.insert(0, str(HOST_TOOLS))
import refresh  # noqa: E402


class RefreshTimeoutTests(unittest.TestCase):
    def test_subprocess_timeout_is_an_actionable_refresh_error(self) -> None:
        with mock.patch.object(
                refresh.subprocess, "run",
                side_effect=subprocess.TimeoutExpired(["/usr/bin/ssh"], 30)):
            with self.assertRaisesRegex(refresh.RefreshError, "ssh timed out after 30 seconds"):
                refresh.run(["/usr/bin/ssh", "fixture"], timeout=30, check=False)


if __name__ == "__main__":
    unittest.main()
