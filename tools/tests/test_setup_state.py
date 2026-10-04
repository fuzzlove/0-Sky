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
