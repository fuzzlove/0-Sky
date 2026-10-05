from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge"))
SPEC = importlib.util.spec_from_file_location(
    "zero_sky_project_setup",
    ROOT / "bridge/0SkyBridge/Resources/Scripts/0sky_project_setup.py",
)
assert SPEC and SPEC.loader
setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(setup)


class SetupStateTests(unittest.TestCase):
    def test_offline_dpkg_builder_requires_build_capable_signed_helper(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            kit = Path(folder)
            helper = kit / "host-mac/runtime/bin/dpkg-deb"
            helper.parent.mkdir(parents=True)
            helper.write_text(
                "#!/bin/sh\necho '0-Sky dpkg-deb compatibility 1.0'\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)
            with mock.patch.object(setup, "KIT", kit):
                with self.assertRaisesRegex(setup.PoCError, "outdated"):
                    setup.require_offline_device_package_builder()
            helper.write_text(
                "#!/bin/sh\necho '0-Sky dpkg-deb compatibility 1.1'\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)
            with mock.patch.object(setup, "KIT", kit):
                with self.assertRaisesRegex(setup.PoCError, "outdated"):
                    setup.require_offline_device_package_builder()
            helper.write_text(
                "#!/bin/sh\necho '0-Sky dpkg-deb compatibility 1.2'\n",
                encoding="utf-8",
            )
            helper.chmod(0o755)
            with mock.patch.object(setup, "KIT", kit):
                self.assertEqual(setup.require_offline_device_package_builder(), helper)

    def test_child_progress_is_streamed_and_still_captured(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            log_file = Path(folder) / "child.log"
            with mock.patch.object(setup, "log"):
                completed = setup.run(
                    [sys.executable, "-c", "print('stage one', flush=True); print('stage two', flush=True)"],
                    capture=True, stream_output=True, log_file=log_file, timeout=10,
                )
            self.assertEqual(completed.returncode, 0)
            self.assertIn(b"stage one", completed.stdout)
            self.assertIn("stage one", log_file.read_text(encoding="utf-8"))
            self.assertIn("stage two", log_file.read_text(encoding="utf-8"))

    def test_interrupted_profile_reuses_its_busy_reserved_port(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            support = root / "support"
            device = {
                "udid": "00000000000000000001", "product_type": "iPhone12,8",
                "product_version": "26.0",
            }
            instance = setup.slug_for(device, None)
            directory = support / "instances" / instance
            directory.mkdir(parents=True)
            (directory / "config.json").write_text(json.dumps({
                "schema": 2, "udid": device["udid"], "instance": instance,
                "ssh_host": "127.0.0.1", "ssh_port": "2222",
            }), encoding="utf-8")
            with mock.patch.object(setup, "SUPPORT", support), \
                    mock.patch.object(setup, "launchagent_bindings", return_value={}), \
                    mock.patch.object(setup, "tcp_free", return_value=False):
                targets = setup.assign_targets([device], [device["udid"]], 2222)
            self.assertEqual(targets[0]["instance"], instance)
            self.assertEqual(targets[0]["port"], 2222)

    def test_new_target_does_not_take_another_profile_reserved_port(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            support = root / "support"
            other = support / "instances/other-device"
            other.mkdir(parents=True)
            (other / "config.json").write_text(json.dumps({"ssh_port": "2222"}))
            device = {
                "udid": "00000000000000000001", "product_type": "iPhone12,8",
                "product_version": "26.0",
            }
            with mock.patch.object(setup, "SUPPORT", support), \
                    mock.patch.object(setup, "launchagent_bindings", return_value={}), \
                    mock.patch.object(setup, "tcp_free", return_value=True):
                targets = setup.assign_targets([device], [device["udid"]], 2222)
            self.assertEqual(targets[0]["port"], 2223)

    def test_interrupted_profile_endpoint_mismatch_fails_before_port_allocation(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            support = root / "support"
            device = {
                "udid": "00000000000000000001", "product_type": "iPhone12,8",
                "product_version": "26.0",
            }
            instance = setup.slug_for(device, None)
            directory = support / "instances" / instance
            directory.mkdir(parents=True)
            (directory / "config.json").write_text(json.dumps({
                "udid": "00000000000000000002", "instance": instance,
                "ssh_host": "127.0.0.1", "ssh_port": "2222",
            }))
            with mock.patch.object(setup, "SUPPORT", support), \
                    mock.patch.object(setup, "launchagent_bindings", return_value={}), \
                    mock.patch.object(setup, "tcp_free") as tcp_free:
                with self.assertRaisesRegex(setup.PoCError, "invalid udid"):
                    setup.assign_targets([device], [device["udid"]], 2222)
            tcp_free.assert_not_called()

    def test_stage_progress_is_private_atomic_and_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "device/setup-state.json"
            report = {
                "target": {"udid": "00000000000000000000", "instance": "test-device"},
                "state_file": str(state), "attempt": 2, "resumed": True,
                "check_only": False, "stages": [], "stage_results": {},
            }
            setup.begin_stage(report, "validate")
            setup.begin_stage(report, "deploy")
            value = json.loads(state.read_text(encoding="utf-8"))
            self.assertEqual(value["status"], "running")
            self.assertEqual(value["last_completed_stage"], "validate")
            self.assertEqual(value["current_stage"], "deploy")
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)

    def test_check_only_does_not_persist_state(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder) / "state.json"
            report = {
                "target": {"udid": "00000000000000000000", "instance": "test-device"},
                "state_file": str(state), "attempt": 1, "resumed": False,
                "check_only": True, "stages": [], "stage_results": {},
            }
            setup.begin_stage(report, "read-only-check")
            self.assertFalse(state.exists())

    def test_successful_read_only_stage_is_not_left_running(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            args = types.SimpleNamespace(
                identity=root / "identity", check=True, no_reboot=False,
                force_dropbear=False, ticket_cache=None,
                require_cached_ticket=False, pair_remotexpc=False,
                resume=False,
            )
            target = {
                "udid": "00000000000000000000", "instance": "test-device",
                "port": 2222, "product_type": "iPhone", "product_version": "27.0",
            }
            completed = types.SimpleNamespace(returncode=0, stdout=b"", stderr=b"")
            with mock.patch.object(setup, "STATE_ROOT", root / "state"), \
                    mock.patch.object(setup, "run", return_value=completed):
                report = setup.process_target(
                    Path("/embedded/python"), target, args, root / "evidence"
                )
            self.assertTrue(report["passed"])
            self.assertEqual(report["stage_results"]["dropbear-procursus"], "passed")


if __name__ == "__main__":
    unittest.main()
