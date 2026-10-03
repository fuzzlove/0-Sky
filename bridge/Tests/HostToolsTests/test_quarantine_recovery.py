#!/usr/bin/env python3
"""Regression coverage for the bounded tweak-quarantine recovery IPC."""
from __future__ import annotations

import json
import pathlib
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]
RUNTIME = ROOT / "bridge" / "DeviceRuntime"
import sys
if str(RUNTIME) not in sys.path:
    sys.path.insert(0, str(RUNTIME))

from zero_sky_core import CoreRuntime  # noqa: E402


class QuarantineRecoveryTests(unittest.TestCase):
    def request(self, runtime, operation, parameters=None, paired=True):
        return runtime.handle_ipc({
            "protocolVersion": 1,
            "requestId": operation + str(time.time_ns()),
            "operation": operation,
            "timestamp": time.time(),
            "parameters": parameters or {},
        }, caller={"paired": paired})

    def test_inventory_is_sanitized_and_retry_is_exact_paired_and_atomic(self):
        with tempfile.TemporaryDirectory() as raw:
            runtime = CoreRuntime(pathlib.Path(raw), telemetry_owner=False)
            runtime.start()
            registry = runtime.paths.jailbreak("/var/lib/srd-runtime/registry.json")
            registry.parent.mkdir(parents=True, exist_ok=True)
            registry.write_text(json.dumps({"quarantined": [{
                "package": "org.example.dynamic",
                "target": "com.apple.springboard",
                "dylib": "/var/jb/Library/MobileSubstrate/DynamicLibraries/Dynamic.dylib",
                "reason": "target exited after injection",
                "sha256": "abc123",
            }]}))

            inventory = self.request(runtime, "getQuarantinedTweaks")
            self.assertTrue(inventory["success"], inventory)
            self.assertEqual(inventory["result"]["quarantines"][0]["dylib"],
                             "Dynamic.dylib")
            parameters = {"package": "org.example.dynamic",
                          "target": "com.apple.springboard"}
            denied = self.request(runtime, "clearTweakQuarantine", parameters,
                                  paired=False)
            self.assertEqual(denied["errorCode"], "AUTHORIZATION_REQUIRED")
            stale = self.request(runtime, "clearTweakQuarantine", {
                **parameters, "target": "com.apple.Preferences"})
            self.assertEqual(stale["errorCode"], "QUARANTINE_CHANGED")

            queued = self.request(runtime, "clearTweakQuarantine", parameters)
            self.assertTrue(queued["success"], queued)
            request_path = runtime.paths.jailbreak(
                "/var/lib/srd-runtime/quarantine-clear.request.json")
            payload = json.loads(request_path.read_text())
            self.assertEqual(payload["package"], "org.example.dynamic")
            self.assertEqual(payload["target"], "com.apple.springboard")
            self.assertEqual(request_path.stat().st_mode & 0o777, 0o600)
            busy = self.request(runtime, "clearTweakQuarantine", parameters)
            self.assertEqual(busy["errorCode"], "RECOVERY_BUSY")
            runtime.close()

    def test_foundational_package_retry_is_refused(self):
        with tempfile.TemporaryDirectory() as raw:
            runtime = CoreRuntime(pathlib.Path(raw), telemetry_owner=False)
            runtime.start()
            registry = runtime.paths.jailbreak("/var/lib/srd-runtime/registry.json")
            registry.parent.mkdir(parents=True, exist_ok=True)
            registry.write_text(json.dumps({"quarantined": [{
                "package": "ellekit", "target": "com.apple.springboard",
                "dylib": "ElleKit.dylib", "reason": "fixture",
            }]}))
            reply = self.request(runtime, "clearTweakQuarantine", {
                "package": "ellekit", "target": "com.apple.springboard"})
            self.assertEqual(reply["errorCode"], "PROTECTED_PACKAGE")
            runtime.close()


if __name__ == "__main__":
    unittest.main()
