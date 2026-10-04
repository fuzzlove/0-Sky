"""Host setup probes fail closed instead of hanging or printing tracebacks."""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge"))
import macos_host_setup as setup  # noqa: E402


class MacSetupTimeoutTests(unittest.TestCase):
    def test_bundled_runtime_is_hash_verified_before_path_activation(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            kit = Path(folder)
            binary = kit / "host-mac/runtime/bin"
            binary.mkdir(parents=True)
            license_path = kit / "host-mac/runtime/licenses/test.txt"
            license_path.parent.mkdir(parents=True)
            license_path.write_text("fixture license\n", encoding="utf-8")
            components = []
            for name in ("python3", "dpkg-deb", "iproxy", "idevice_id"):
                path = binary / name
                path.write_text("#!/bin/sh\n", encoding="utf-8")
                path.chmod(0o755)
                components.append({"name": name,
                                   "path": path.relative_to(kit).as_posix(),
                                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                   "architectures": ["arm64", "x86_64"],
                                   "license": license_path.relative_to(kit).as_posix()})
            payloads = {}
            for architecture in ("arm64", "x86_64"):
                path = kit / f"host-mac/runtime/python/{architecture}/python/bin/python3.12"
                path.parent.mkdir(parents=True)
                path.write_text("#!/bin/sh\n", encoding="utf-8")
                path.chmod(0o755)
                payloads[architecture] = {
                    "path": path.relative_to(kit).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            components[0]["payloads"] = payloads
            manifest = kit / "host-mac/HOST_RUNTIME_MANIFEST.json"
            manifest.write_text(json.dumps({"schema": 2, "platform": "macOS",
                                            "components": components}), encoding="utf-8")
            with mock.patch.object(setup, "KIT", kit), \
                    mock.patch.object(setup, "BUNDLED_BIN", binary), \
                    mock.patch.dict(setup.os.environ, {"PATH": "/usr/bin"}):
                self.assertTrue(setup.activate_bundled_runtime())
                self.assertEqual(setup.os.environ["PATH"].split(":")[0], str(binary))
                (binary / "dpkg-deb").write_text("changed", encoding="utf-8")
                with self.assertRaisesRegex(SystemExit, "manifest validation"):
                    setup.activate_bundled_runtime()

    def test_homebrew_bootstrap_refuses_moving_remote_script(self) -> None:
        with mock.patch.object(setup, "locate_brew", return_value=None), \
                mock.patch.object(setup, "run") as run:
            with self.assertRaisesRegex(SystemExit, "disabled"):
                setup.install_homebrew()
        run.assert_not_called()

    def test_bundled_dependency_installer_does_not_execute_remote_bootstrap(self) -> None:
        installer = (ROOT / "bridge" / "0SkyBridge" / "Resources" / "Scripts" /
                     "Install 0-Sky Dependencies.command").read_text(encoding="utf-8")
        self.assertNotIn("raw.githubusercontent.com/Homebrew/install", installer)
        self.assertIn("moving bootstrap script", installer)
        self.assertNotIn("brew\" install", installer)
        self.assertIn("tools/build_host_runtime.py", installer)
        self.assertIn("Expected path:", installer)

    def test_runtime_repair_message_explains_binary_and_source_paths(self) -> None:
        self.assertIn("four-file release", setup.BUNDLED_RUNTIME_REPAIR)
        self.assertIn("tools/build_host_runtime.py", setup.BUNDLED_RUNTIME_REPAIR)
        self.assertIn("Do not install Homebrew", setup.BUNDLED_RUNTIME_REPAIR)

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
