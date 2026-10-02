"""A worker heartbeat only carries a fresh device-bound SSH UAT receipt."""
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
    "usb_identity", "pinned_public_key", "root_shell", "server_process",
    "localhost_listener", "file_round_trip", "cleanup", "reconnect")}


class HostSSHUATReceiptTests(unittest.TestCase):
    def test_receipt_is_fresh_private_and_bound_to_device_and_host_key(self) -> None:
        worker = runpy.run_path(str(WORKER), run_name="ssh_uat_worker_test")
        read = worker["host_ssh_uat_status"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ssh.json"
            value = {"schema": 1, "device_digest": hashlib.sha256(b"test-device").hexdigest(),
                     "host_key_fingerprint": "test-pinned-key", "timestamp": int(time.time()),
                     "result": "PASS", "checks": CHECKS, "transport": "configured"}
            def save() -> None:
                path.write_text(json.dumps(value))
                path.chmod(0o600)
            with patch.dict(read.__globals__, {
                "SSH_UAT_RECEIPT": path, "DEVICE_UDID": "test-device",
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
                value["checks"]["reconnect"] = False
                save()
                self.assertEqual(read()["result"], "UNVERIFIED")
                value["checks"]["reconnect"] = True
                save()
                self.assertEqual(read()["result"], "PASS")


if __name__ == "__main__":
    unittest.main()
