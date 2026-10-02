"""Regression tests for atomic Control inventory-helper deployment."""
from __future__ import annotations

import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "addons/PoC/deploy_control_358.py"


def load_script():
    sys.path.insert(0, str(SCRIPT.parent))
    spec = importlib.util.spec_from_file_location("deploy_control_appctl_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Result:
    def __init__(self, returncode: int = 0, stdout: bytes = b"") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = b""


class FakeNamespace:
    def __init__(self, *, schema_valid: bool = True) -> None:
        self.commands: list[str] = []
        self.schema_valid = schema_valid

    def ssh(self, command: str, **kwargs) -> Result:
        self.commands.append(command)
        if command.startswith("test -f "):
            return Result(0)
        if " list --json" in command:
            payload = ({"applications": [], "tweaks": []} if self.schema_valid
                       else {"applications": []})
            return Result(stdout=json.dumps(payload).encode())
        return Result()


class InventoryHelperDeploymentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_script()

    def test_post_commit_validation_uses_supported_list_command(self) -> None:
        namespace = FakeNamespace()
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "appctl.py"
            source.write_text("print('fixture')\n", encoding="utf-8")
            digest = self.module.hashlib.sha256(source.read_bytes()).hexdigest()
            with patch.object(self.module, "remote_python",
                              side_effect=[digest, "OK"]):
                result = self.module.install_appctl({"ssh": namespace.ssh}, source)
        self.assertEqual(result["applications"], 0)
        self.assertEqual(result["tweaks"], 0)
        self.assertTrue(any(" list --json" in item for item in namespace.commands))
        self.assertFalse(any(" inventory" in item for item in namespace.commands))

    def test_invalid_post_commit_schema_restores_existing_helper(self) -> None:
        namespace = FakeNamespace(schema_valid=False)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "appctl.py"
            source.write_text("print('fixture')\n", encoding="utf-8")
            digest = self.module.hashlib.sha256(source.read_bytes()).hexdigest()
            with patch.object(self.module, "remote_python",
                              side_effect=[digest, "OK"]):
                with self.assertRaisesRegex(RuntimeError, "invalid schema"):
                    self.module.install_appctl({"ssh": namespace.ssh}, source)
        restore = [item for item in namespace.commands
                   if item.startswith("cp -p ") and ".new." not in item]
        self.assertEqual(len(restore), 1)
        self.assertIn("backups/crypstore-appctl.py.", restore[0])


if __name__ == "__main__":
    unittest.main()
