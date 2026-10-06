"""The reviewed Link worker must restore prior code after a post-mutation fault."""
from __future__ import annotations

import hashlib
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch


WORKER = (Path(__file__).resolve().parents[2] /
          "bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py")
LINK_ID = "codes.liquidsky.research.zerosky"


class LinkWorkerTransactionTests(unittest.TestCase):
    def test_generic_link_install_seals_first_party_registrar_marker(self) -> None:
        source = WORKER.read_text(encoding="utf-8")
        self.assertIn(
            "if bundle_id in NATIVE_FIRST_PARTY:\n"
            "        prepare_native_control(app, bundle_id)",
            source,
        )
        self.assertIn(
            'if bundle_id == "com.liquidsky.CrypStore" else\n'
            "                      register_and_link",
            source,
        )

    def test_registration_failure_restores_prior_link(self) -> None:
        worker = runpy.run_path(str(WORKER), run_name="link_worker_test")
        install = worker["process_link_install"]
        globals_ = install.__globals__
        raw = b"reviewed link fixture" * 20
        digest = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            previous = root / "previous/ZeroSky.app"
            previous.mkdir(parents=True)
            calls: list[str] = []

            def fake_run(argv, **_kwargs):
                if argv[0] == "/usr/bin/ditto":
                    (Path(argv[-1]) / "Payload/ZeroSky.app").mkdir(parents=True)

            def fail_registration(*_args, **_kwargs):
                calls.append("register")
                raise RuntimeError("registration interrupted")

            def rollback(_previous, _job_dir, bundle_id):
                self.assertEqual((_previous, bundle_id), (previous, LINK_ID))
                calls.append("rollback")
                return "VERIFIED"

            replacements = {
                "JOBS": root / "jobs",
                "set_status": lambda *_args: None,
                "fetch_ipa": lambda _job, path: path.write_bytes(raw),
                "normalize_ipa_archive": lambda _path: False,
                "preflight_workspace": lambda _path: None,
                "preflight_device_workspace": lambda _app: None,
                "run": fake_run,
                "sign_app": lambda *_args: (LINK_ID, "ZeroSky", "ZeroSky.app", {}),
                "prepare_native_control": lambda *_args: None,
                "verify_control_entitlements": lambda *_args: None,
                "evaluate_control_compatibility": lambda _path: {"result": "COMPATIBLE"},
                "snapshot_native_control": lambda *_args: previous,
                "build_install_cryptex": lambda *_args: ("verified-cryptex", root),
                "locate_mount": lambda *_args: "/verified/mount/ZeroSky.app",
                "foreground_launch_policy": lambda *_args: "REQUIRED",
                "register_and_link": fail_registration,
                "rollback_native_control": rollback,
            }
            with patch.dict(globals_, replacements):
                with self.assertRaises(worker["ControlInstallFailed"]) as failure:
                    install("link-test-job", {"source_sha256": digest,
                                             "required_entitlements": {"get-task-allow": True}})
            self.assertEqual(failure.exception.rollback, "VERIFIED")
            self.assertEqual(calls, ["register", "rollback"])


if __name__ == "__main__":
    unittest.main()
