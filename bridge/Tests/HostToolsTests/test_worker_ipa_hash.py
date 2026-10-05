from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest import mock


WORKER = (Path(__file__).resolve().parents[2] / "KitScripts/automation/"
          "CrypStoreAutomation/crypstore_worker.py")
SPEC = importlib.util.spec_from_file_location("crypstore_worker_hash_test", WORKER)
worker = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(worker)


class WorkerIPAHashTests(unittest.TestCase):
    def test_requested_hash_must_match_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / "input.ipa"
            ipa.write_bytes(b"reviewed fixture bytes")
            expected = hashlib.sha256(ipa.read_bytes()).hexdigest()
            self.assertEqual(worker.verify_requested_ipa_sha256(ipa, expected), expected)
            ipa.write_bytes(b"tampered fixture bytes")
            with self.assertRaisesRegex(RuntimeError, "SHA-256 differs"):
                worker.verify_requested_ipa_sha256(ipa, expected)

    def test_invalid_hash_format_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            ipa = Path(folder) / "input.ipa"
            ipa.write_bytes(b"fixture")
            with self.assertRaisesRegex(RuntimeError, "SHA-256 differs"):
                worker.verify_requested_ipa_sha256(ipa, "bad-hash")

    def test_visible_app_requires_foreground_launch(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "Visible.app"
            app.mkdir()
            (app / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.example.visible",
            }))
            self.assertEqual(worker.foreground_launch_policy(app), "REQUIRED")

    def test_hidden_companion_uses_registration_and_extension_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "Helper.app"
            app.mkdir()
            (app / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.example.helper",
                "SBAppTags": ["hidden"],
            }))
            self.assertEqual(worker.foreground_launch_policy(
                app, "controlled-exit-v1"), "CONTROLLED_EXIT")

    def test_malformed_presentation_tags_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "Broken.app"
            app.mkdir()
            (app / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.example.broken",
                "SBAppTags": "hidden",
            }))
            with self.assertRaisesRegex(RuntimeError, "presentation tags"):
                worker.foreground_launch_policy(app)

    def test_deferred_result_retries_only_result_delivery(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(worker, "JOBS", Path(folder)), \
                mock.patch.object(worker, "remote_result") as publish, \
                mock.patch.object(worker, "cleanup_job_artifacts") as cleanup:
            job_id = "180c33a5-96ec-471b-9be9-ffa1a97b8a40"
            value = {"status": 125, "stderr": "disk full"}
            worker.defer_remote_result(job_id, value)
            self.assertTrue(worker.flush_deferred_result(job_id))
            publish.assert_called_once_with(job_id, value)
            cleanup.assert_called_once_with(Path(folder) / job_id)
            self.assertFalse(worker.pending_result_path(job_id).exists())

    def test_deferred_result_stays_durable_when_device_is_unwritable(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(worker, "JOBS", Path(folder)), \
                mock.patch.object(worker, "remote_result", side_effect=RuntimeError("ENOSPC")), \
                mock.patch.object(worker, "log"):
            job_id = "180c33a5-96ec-471b-9be9-ffa1a97b8a40"
            value = {"status": 125, "stderr": "disk full"}
            worker.defer_remote_result(job_id, value)
            self.assertFalse(worker.flush_deferred_result(job_id))
            self.assertEqual(json.loads(worker.pending_result_path(job_id).read_text()), value)

    def test_device_space_requirement_has_transactional_floor(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "Fixture.app"
            app.mkdir()
            (app / "Fixture").write_bytes(b"fixture")
            required, payload, image = worker.required_device_install_bytes(app)
            self.assertEqual(payload, len(b"fixture"))
            self.assertEqual(image, 384 * 1024 * 1024)
            self.assertGreaterEqual(required, worker.MIN_DEVICE_INSTALL_HEADROOM)

    def test_device_space_preflight_blocks_before_mutation(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(worker, "device_free_space_bytes", return_value=128 * 1024 * 1024), \
                mock.patch.object(worker, "log"):
            app = Path(folder) / "Fixture.app"
            app.mkdir()
            (app / "Fixture").write_bytes(b"fixture")
            with self.assertRaisesRegex(RuntimeError, "device has insufficient free space"):
                worker.preflight_device_workspace(app)

    def test_device_space_preflight_accepts_sufficient_space(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(worker, "device_free_space_bytes", return_value=4 * 1024**3), \
                mock.patch.object(worker, "log"):
            app = Path(folder) / "Fixture.app"
            app.mkdir()
            (app / "Fixture").write_bytes(b"fixture")
            worker.preflight_device_workspace(app)

    def test_generic_install_preflights_device_before_registration_retirement(self):
        source = WORKER.read_text(encoding="utf-8")
        preflight = source.index('stage("Checking device workspace"')
        retirement = source.index('stage("Retiring prior registration"')
        self.assertLess(preflight, retirement)

    def test_control_native_install_uses_exact_device_devicectl(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            app = root / "Path With Spaces" / "CrypStore.app"
            app.mkdir(parents=True)
            job = root / "job"
            job.mkdir()

            def execute(argv, **kwargs):
                if argv == ["/usr/bin/xcrun", "--find", "devicectl"]:
                    return subprocess.CompletedProcess(
                        argv, 0, b"/Applications/Xcode.app/Contents/Developer/usr/bin/devicectl\n", b"")
                result = Path(argv[argv.index("--json-output") + 1])
                result.write_text(json.dumps({
                    "result": {"installedApplications": [{"bundleIdentifier": "fixture"}]}
                }))
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            with mock.patch.object(worker, "DEVICE_UDID", "selected-device"), \
                    mock.patch.object(worker, "run", side_effect=execute) as run:
                worker.install_app_with_devicectl(app, job)

            install = run.call_args_list[1].args[0]
            self.assertEqual(install[0],
                             Path("/Applications/Xcode.app/Contents/Developer/usr/bin/devicectl"))
            self.assertEqual(install[install.index("--device") + 1], "selected-device")
            self.assertEqual(install[install.index("--device") + 2], str(app))
            self.assertNotIn("pymobiledevice3", " ".join(map(str, install)))

    def test_fresh_link_uses_bounded_cryptex_registration(self):
        source = WORKER.read_text(encoding="utf-8")
        start = source.index("def process_link_install(")
        end = source.index("\ndef ", start + 5)
        implementation = source[start:end]
        self.assertIn("register_and_link(", implementation)
        self.assertNotIn("install_native_control(", implementation)
        self.assertIn("locate_mount(", implementation)

    def test_devicectl_requirement_is_actionable(self):
        missing = subprocess.CompletedProcess(
            ["/usr/bin/xcrun", "--find", "devicectl"], 72, b"", b"missing")
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch.object(worker, "DEVICE_UDID", "selected-device"), \
                mock.patch.object(worker, "run", return_value=missing):
            with self.assertRaisesRegex(RuntimeError, "Install the complete supported Xcode"):
                worker.install_app_with_devicectl(Path(folder) / "Control.app", Path(folder))

    def test_fixed_cryptex_image_uses_transfer_sized_deadline(self):
        source = WORKER.read_text(encoding="utf-8")
        start = source.index("def build_install_cryptex(")
        end = source.index("\ndef ", start + 5)
        implementation = source[start:end]
        self.assertIn("timeout=1020", implementation)
        self.assertNotIn("timeout=300", implementation)
