"""Regression checks for the reviewed Filza installer in Bridge setup."""
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import sys
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[2] / "0SkyBridge/Resources/Scripts/0sky_project_setup.py"
spec = importlib.util.spec_from_file_location("zero_sky_project_setup_filza_test", SOURCE)
setup = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = setup
spec.loader.exec_module(setup)


class FilzaSetupTests(unittest.TestCase):
    def setUp(self):
        self.target = {"udid": "TEST-DEVICE-IDENTIFIER-0001", "instance": "test"}
        self.identity = Path("/test/identity")
        self.payload = {
            "sealed_executable_sha256": "a" * 64,
            "sealed_info_sha256": "b" * 64,
        }
        self.current = {
            "path": "/private/var/containers/Bundle/Application/TEST/FilzaFixed.6907.app",
            "version": "4.0", "registered": True, "executable": True,
        }

    def test_old_filza_app_never_counts_as_current(self):
        old = dict(self.current, path=self.current["path"].replace(
            "FilzaFixed.6907.app", "Filza.app"))
        with mock.patch.object(setup, "filza_payload", return_value=self.payload), \
             mock.patch.object(setup, "app_info", return_value=old), \
             mock.patch.object(setup, "remote") as remote:
            self.assertEqual(setup.filza_current(self.target, self.identity), {})
            remote.assert_not_called()

    def test_stale_launch_services_bytes_never_count_as_current(self):
        result = subprocess.CompletedProcess([], 0, b'{"reviewed_bytes":false}', b'')
        with mock.patch.object(setup, "filza_payload", return_value=self.payload), \
             mock.patch.object(setup, "app_info", return_value=self.current), \
             mock.patch.object(setup, "remote", return_value=result) as remote:
            self.assertEqual(setup.filza_current(self.target, self.identity), {})
            args = shlex.split(remote.call_args.args[2])
            self.assertEqual(args[:2], ["/var/jb/usr/bin/python3", "-c"])
            compile(args[2], "filza-device-probe", "exec")
            self.assertEqual(args[-2:], ["a" * 64, "b" * 64])

    def test_reviewed_registration_requires_no_legacy_cryptex(self):
        result = subprocess.CompletedProcess([], 0, b'{"reviewed_bytes":true}', b'')
        with mock.patch.object(setup, "filza_payload", return_value=self.payload), \
             mock.patch.object(setup, "app_info", return_value=self.current), \
             mock.patch.object(setup, "remote", return_value=result), \
             mock.patch.object(setup, "legacy_filza_cryptex_state", return_value="known"):
            self.assertEqual(setup.filza_current(self.target, self.identity), {})
        with mock.patch.object(setup, "filza_payload", return_value=self.payload), \
             mock.patch.object(setup, "app_info", return_value=self.current), \
             mock.patch.object(setup, "remote", return_value=result), \
             mock.patch.object(setup, "legacy_filza_cryptex_state", return_value="absent"):
            self.assertEqual(setup.filza_current(self.target, self.identity), self.current)

    def test_legacy_cryptex_conflict_blocks_install_before_mutation(self):
        with mock.patch.object(setup, "filza_payload", return_value=self.payload), \
             mock.patch.object(setup, "legacy_filza_cryptex_state", return_value="conflict"), \
             mock.patch.object(setup, "run") as run:
            with self.assertRaisesRegex(setup.PoCError, "known single-app generation"):
                setup.install_filza(Path("/test/python"), self.target, self.identity, Path("/tmp"))
            run.assert_not_called()

    def test_install_retires_only_known_legacy_cryptex_after_registration(self):
        states = iter(("known", "known", "absent"))
        registration = subprocess.CompletedProcess([], 0, b'{"registered_path":"reviewed","reviewed_bytes":true}', b'')
        with mock.patch.object(setup, "filza_payload", return_value=self.payload), \
             mock.patch.object(setup, "legacy_filza_cryptex_state", side_effect=lambda *_: next(states)), \
             mock.patch.object(setup, "run") as run, \
             mock.patch.object(setup, "remote", return_value=registration) as remote, \
             mock.patch.object(setup, "filza_current", return_value=self.current):
            self.assertEqual(setup.install_filza(
                Path("/test/python"), self.target, self.identity, Path("/tmp")), self.current)
            self.assertEqual(run.call_count, 2)
            self.assertIn(setup.FILZA_LEGACY_CRYPTEX_ID, run.call_args.args[0])
            self.assertIn(self.target["udid"], run.call_args.args[0])
            self.assertEqual(remote.call_count, 1)
            args = shlex.split(remote.call_args.args[2])
            compile(args[2], "filza-device-registration", "exec")
            self.assertEqual(args[-2:], ["a" * 64, "b" * 64])


if __name__ == "__main__":
    unittest.main()
