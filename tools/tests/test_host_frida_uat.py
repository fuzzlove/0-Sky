"""A host Frida receipt proves only fresh, device-bound read-only enumeration."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import runpy
import tempfile
import time
import unittest
from unittest.mock import patch


WORKER = (Path(__file__).resolve().parents[2] /
          "bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py")
CHECKS = {name: True for name in (
    "usb_identity", "artifact_hash", "server_process", "localhost_listener",
    "host_version", "process_enumeration")}


class HostFridaReceiptTests(unittest.TestCase):
    def test_receipt_rejects_stale_mismatched_and_public_evidence(self) -> None:
        worker = runpy.run_path(str(WORKER), run_name="frida_uat_worker_test")
        read = worker["host_frida_uat_status"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "frida.json"
            value = {"schema": 1, "device_digest": hashlib.sha256(b"test-device").hexdigest(),
                     "host_key_fingerprint": "test-pinned-key", "timestamp": int(time.time()),
                     "result": "PASS", "checks": CHECKS,
                     "transport": "exact_usb_iproxy", "host_version": "17.18.0",
                     "device_version": "17.18.0", "scope": "read_only_process_enumeration"}

            def save() -> None:
                path.write_text(json.dumps(value))
                path.chmod(0o600)

            with patch.dict(read.__globals__, {
                    "FRIDA_UAT_RECEIPT": path, "DEVICE_UDID": "test-device",
                    "HOST_KEY_FINGERPRINT": "test-pinned-key"}):
                self.assertEqual(read()["result"], "UNVERIFIED")
                save()
                self.assertEqual(read()["result"], "PASS")
                path.chmod(0o644)
                self.assertEqual(read()["result"], "UNVERIFIED")
                save()
                value["timestamp"] -= 7200
                save()
                self.assertEqual(read()["result"], "UNVERIFIED")
                value["timestamp"] = int(time.time())
                value["device_digest"] = hashlib.sha256(b"other-device").hexdigest()
                save()
                self.assertEqual(read()["result"], "UNVERIFIED")
                value["device_digest"] = hashlib.sha256(b"test-device").hexdigest()
                value["host_key_fingerprint"] = "wrong-key"
                save()
                self.assertEqual(read()["result"], "UNVERIFIED")
                value["host_key_fingerprint"] = "test-pinned-key"
                value["checks"]["process_enumeration"] = False
                save()
                self.assertEqual(read()["result"], "UNVERIFIED")
                value["checks"]["process_enumeration"] = True
                value["scope"] = "arbitrary_app_attach"
                save()
                self.assertEqual(read()["result"], "UNVERIFIED")


if __name__ == "__main__":
    unittest.main()
