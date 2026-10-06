"""Locked Theos preflight failures include an actionable repair sequence."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools import theos_preflight


class TheosPreflightTests(unittest.TestCase):
    def test_missing_checkout_names_lock_and_exact_clone_commands(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / "theos"
            with self.assertRaises(theos_preflight.TheosError) as caught:
                theos_preflight.verify(missing)
        self.assertEqual(caught.exception.code, "THEOS_NOT_FOUND")
        self.assertIn("git clone --recursive", caught.exception.remediation)
        self.assertIn("dd5c14bb9d91311e221d51b5bfb8c9e5948156db",
                      caught.exception.remediation)
        self.assertIn("--theos '/absolute/path/to/theos'",
                      caught.exception.remediation)


if __name__ == "__main__":
    unittest.main()
