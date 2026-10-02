from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "build_host_mitmproxy.py"
SPEC = importlib.util.spec_from_file_location("build_host_mitmproxy", SCRIPT)
builder = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(builder)


class HostMitmproxyBuildTests(unittest.TestCase):
    def test_rejects_unreviewed_source_revision(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder)
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(source), "config", "user.name", "0-Sky Test"], check=True)
            (source / "README").write_text("fixture\n")
            subprocess.run(["git", "-C", str(source), "add", "README"], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-q", "-m", "fixture"], check=True)
            subprocess.run(["git", "-C", str(source), "remote", "add", "origin", builder.UPSTREAM], check=True)
            with self.assertRaisesRegex(RuntimeError, "reviewed upstream revision"):
                builder.verify_source(source)

    def test_private_package_index_is_not_inherited(self):
        with patch.dict(os.environ, {"PIP_INDEX_URL": "https://user:secret@example.invalid/simple"}):
            environment = builder.pip_environment()
        self.assertNotIn("PIP_INDEX_URL", environment)
        self.assertEqual(environment["PIP_CONFIG_FILE"], os.devnull)

    def test_activation_keeps_previous_environment(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "mitmproxy-versioned"
            target.mkdir()
            current = root / "mitmproxy-current"
            current.mkdir()
            (current / "marker").write_text("previous")
            backup = builder.activate(target, current)
            self.assertTrue(current.is_symlink())
            self.assertEqual(current.resolve(), target.resolve())
            self.assertEqual((backup / "marker").read_text(), "previous")


if __name__ == "__main__":
    unittest.main()
