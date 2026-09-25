from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "bridge/zero_sky_user_config.py"
spec = importlib.util.spec_from_file_location("portable_user_config", MODULE)
assert spec and spec.loader
config = importlib.util.module_from_spec(spec)
spec.loader.exec_module(config)


class PortabilityConfigTests(unittest.TestCase):
    def test_precedence_relative_paths_and_unrelated_working_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "another-user"
            home.mkdir()
            file = root / "settings/config.json"
            file.parent.mkdir()
            file.write_text(json.dumps({
                "schema": 1,
                "paths": {"support": "saved-support"},
                "defaults": {"base_port": 3333},
            }))
            file.chmod(0o600)
            environment = {"ZERO_SKY_SUPPORT": str(root / "environment-support"),
                           "ZERO_SKY_BASE_PORT": "4444"}
            previous = Path.cwd()
            try:
                os.chdir(home)
                result = config.load(ROOT, file, environment=environment, home=home)
                self.assertEqual(result["paths"]["support"],
                                 str((file.parent / "saved-support").resolve()))
                self.assertEqual(result["defaults"]["base_port"], 3333)
                result = config.load(ROOT, file, overrides={
                    "paths": {"support": str(root / "cli-support")},
                    "defaults": {"base_port": 5555},
                }, environment=environment, home=home)
                self.assertEqual(result["paths"]["support"], str((root / "cli-support").resolve()))
                self.assertEqual(result["defaults"]["base_port"], 5555)
                self.assertTrue(result["paths"]["venv"].startswith(str(home.resolve())))
            finally:
                os.chdir(previous)

    def test_public_view_hides_local_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary) / "another-user"
            home.mkdir()
            value = config.defaults(ROOT, home)
            public = config.public(value, home / "config.json")
            self.assertEqual(public["profile"]["user"], "<local-user>")
            self.assertEqual(public["installation"]["host"], "<local-host>")
            self.assertEqual(public["paths"]["support"],
                             "~/Library/Application Support/0-Sky")

    def test_relative_environment_path_is_rejected(self):
        with self.assertRaises(config.UserConfigError):
            config.load(ROOT, environment={"ZERO_SKY_SUPPORT": "relative/support"})


if __name__ == "__main__":
    unittest.main()
