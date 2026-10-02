"""Contract tests for the bundled Control installer and rollback coordinator."""
from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bridge/DeviceRuntime"))
from zero_sky_core.control_install_policy import decide
from zero_sky_core import control_install_service
from zero_sky_core.control_install_transaction import EVIDENCE, execute
from zero_sky_core.control_payload import PayloadError, create_manifest, verify_manifest


ROOT = Path(__file__).resolve().parents[2]
IPA = Path(__file__).resolve().parent / "srdsh-work/components/zero-sky/kit/packages/Commissary-Universal.ipa"
ENTITLEMENTS = ROOT / "control/TrollStoreLite/entitlements.plist"


def environment():
    return {"os_major": 27, "architecture": "arm64", "srd_authorized": True,
            "bootstrap_ready": True, "paired_mac_verified": True, "worker_connected": True,
            "free_mb": 2048, "payload_mb": 2,
            "missing_dependencies": [], "incompatible_dependencies": [],
            "transactional_backend": True, "rollback_source_verified": True}


def installed(build="3.4.4.4", **changes):
    value = {"bundle_id": "com.liquidsky.CrypStore", "build": build,
             "executable": True, "resources": True, "signature": True, "entitlements": True,
             "registration": True, "dependencies": True, "services": True,
             "launch": True, "link_communication": True}
    value.update(changes)
    return value


class PolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = create_manifest(IPA, ENTITLEMENTS)

    def test_actions_and_blockers(self):
        cases = [
            ("fresh", {}, None, "INSTALL", "FRESH"),
            ("arm64e device runs arm64 slice", {"architecture": "arm64e"}, None,
             "INSTALL", "FRESH"),
            ("current", {}, installed(), "NO_ACTION", "CURRENT"),
            ("older", {}, installed("3.4.3"), "UPDATE", "OLDER_INSTALLED"),
            ("newer", {}, installed("3.5"), "BLOCK", "NEWER_INSTALLED"),
            ("corrupt", {}, installed(executable=False), "REPAIR", "DAMAGED"),
            ("damaged resource", {}, installed(resources=False), "REPAIR", "DAMAGED"),
            ("unregistered", {}, installed(registration=False), "REPAIR", "DAMAGED"),
            ("unlaunched", {}, installed(launch=False), "REPAIR", "DAMAGED"),
            ("wrong identity", {}, installed(bundle_id="other"), "BLOCK", "INSTALLED_IDENTITY"),
            ("unknown version", {}, installed("beta"), "BLOCK", "VERSION_UNKNOWN"),
            ("unsupported OS", {"os_major": 28}, None, "BLOCK", "UNSUPPORTED_OS"),
            ("wrong CPU", {"architecture": "x86_64"}, None, "BLOCK", "ARCHITECTURE"),
            ("no SRD", {"srd_authorized": False}, None, "BLOCK", "SRD_AUTHORIZATION"),
            ("no bootstrap", {"bootstrap_ready": False}, None, "BLOCK", "BOOTSTRAP"),
            ("no Mac", {"paired_mac_verified": False}, None, "BLOCK", "BRIDGE_DISCONNECTED"),
            ("worker lost", {"worker_connected": False}, None, "BLOCK", "BRIDGE_DISCONNECTED"),
            ("native backend without legacy registrar", {"appregistrard_ready": False}, None,
             "INSTALL", "FRESH"),
            ("low disk", {"free_mb": 1}, None, "BLOCK", "DISK_SPACE"),
            ("missing library", {"missing_dependencies": ["libExample.dylib"]}, None,
             "BLOCK", "DEPENDENCY_MISSING"),
            ("bad dependency", {"incompatible_dependencies": ["rootful script"]}, None,
             "BLOCK", "DEPENDENCY_INCOMPATIBLE"),
            ("no transaction", {"transactional_backend": False}, None,
             "BLOCK", "BACKEND_UNAVAILABLE"),
            ("no snapshot", {"rollback_source_verified": False}, installed("3.4.3"),
             "BLOCK", "ROLLBACK_SOURCE"),
        ]
        for name, changes, existing, action, code in cases:
            with self.subTest(name=name):
                env = environment()
                env.update(changes)
                result = decide(self.manifest, env, existing)
                self.assertEqual((result.action, result.code), (action, code))

    def test_installed_resource_integrity_detects_damage(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "CrypStore.app"
            app.mkdir()
            info = plistlib.dumps({"CFBundleIdentifier": "com.liquidsky.CrypStore",
                                   "CFBundleVersion": "3.5.0.2",
                                   "CFBundleExecutable": "CrypStore"})
            (app / "Info.plist").write_bytes(info)
            (app / "CrypStore").write_bytes(b"resigned executable")
            (app / "trollstorehelper").write_bytes(b"resigned helper")
            icon = app / "AppIcon.png"
            icon.write_bytes(b"reviewed icon")
            files = {"Payload/CrypStore.app/Info.plist": hashlib.sha256(info).hexdigest(),
                     "Payload/CrypStore.app/AppIcon.png": hashlib.sha256(icon.read_bytes()).hexdigest(),
                     "Payload/CrypStore.app/CrypStore": hashlib.sha256(b"source executable").hexdigest(),
                     "Payload/CrypStore.app/trollstorehelper": hashlib.sha256(b"source helper").hexdigest()}
            manifest = {"files": files, "services": []}
            with patch.object(control_install_service, "registered_path", return_value=app):
                self.assertTrue(control_install_service.installed_control({}, manifest)["resources"])
                icon.write_bytes(b"damaged icon")
                self.assertFalse(control_install_service.installed_control({}, manifest)["resources"])


class PayloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = create_manifest(IPA, ENTITLEMENTS)

    def test_real_payload_and_repeated_verification(self):
        self.assertEqual(verify_manifest(IPA, self.manifest)["CFBundleIdentifier"],
                         "com.liquidsky.CrypStore")
        self.assertEqual(verify_manifest(IPA, self.manifest)["CFBundleVersion"], "3.4.4.4")

    def test_hash_mismatch_and_tampering(self):
        altered = copy.deepcopy(self.manifest)
        altered["ipa_sha256"] = "0" * 64
        with self.assertRaises(PayloadError):
            verify_manifest(IPA, altered)
        altered = copy.deepcopy(self.manifest)
        altered["files"]["Payload/CrypStore.app/Info.plist"] = "0" * 64
        with self.assertRaises(PayloadError):
            verify_manifest(IPA, altered)

    def test_symlink_source_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            shortcut = Path(temporary) / "control.ipa"
            shortcut.symlink_to(IPA)
            with self.assertRaises(PayloadError):
                create_manifest(shortcut, ENTITLEMENTS)


class FakeBackend:
    name = "paired-srd-worker-v1"

    def __init__(self, fail_at=None):
        self.fail_at = fail_at
        self.calls = []

    def _call(self, name):
        self.calls.append(name)
        if self.fail_at == name:
            raise RuntimeError(name + " failed")

    def snapshot(self): self._call("snapshot"); return "prior"
    def stage(self): self._call("stage"); return "payload"
    def install(self, staged): self._call("install")
    def register(self): self._call("register")
    def configure(self): self._call("configure")
    def verify(self):
        self._call("verify")
        return {key: True for key in EVIDENCE}
    def rollback(self, snapshot): self._call("rollback")
    def verify_rollback(self, snapshot): self._call("verify_rollback"); return True
    def cleanup(self, staged): self._call("cleanup")


class TransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = create_manifest(IPA, ENTITLEMENTS)

    def test_fresh_install_and_repeated_press(self):
        decision = decide(self.manifest, environment(), None)
        first = execute(decision, FakeBackend())
        self.assertEqual(first.result, "INSTALLED_AND_VERIFIED")
        self.assertTrue(all(first.evidence.values()))
        current = decide(self.manifest, environment(), installed())
        backend = FakeBackend()
        second = execute(current, backend)
        self.assertEqual(second.result, "ALREADY_INSTALLED_AND_VERIFIED")
        self.assertEqual(backend.calls, ["verify"])

    def test_registration_and_transport_failures_roll_back(self):
        decision = decide(self.manifest, environment(), installed("3.4.3"))
        for stage in ("install", "register", "configure", "verify"):
            with self.subTest(stage=stage):
                backend = FakeBackend(stage)
                result = execute(decision, backend)
                self.assertEqual((result.result, result.rollback), ("FAILED", "VERIFIED"))
                self.assertIn("verify_rollback", backend.calls)

    def test_staging_failure_does_not_modify_or_roll_back(self):
        decision = decide(self.manifest, environment(), None)
        backend = FakeBackend("stage")
        result = execute(decision, backend)
        self.assertEqual(result.result, "FAILED")
        self.assertNotIn("install", backend.calls)
        self.assertNotIn("rollback", backend.calls)


if __name__ == "__main__":
    unittest.main()
