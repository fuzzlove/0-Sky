"""Frida evidence may improve a probe, but cannot imply full toolkit UAT."""
import unittest
from unittest.mock import patch
import hashlib
import json
from pathlib import Path
import tempfile

import paired_frida_probe as probe


UDID = "test-device-0001"


async def identity(_udid):
    return {"udid": UDID, "version": "27.0", "build": "test"}


class PairedFridaProbeTests(unittest.TestCase):
    def test_rejects_device_identifier_path_escape(self):
        with self.assertRaisesRegex(ValueError, "INVALID_UDID"):
            probe.run("paired-instance", "../../outside")

    def run_probe(self, device, handshake=None):
        with (patch.object(probe, "profiles", return_value={UDID: (None, {})}),
              patch.object(probe, "usb_identity", side_effect=identity),
              patch.object(probe, "worker_namespace", return_value={}),
              patch.object(probe, "remote_probe", return_value=device),
              patch.object(probe, "frida_handshake", return_value=handshake or
                           {"result": "PASS", "host_version": "17.18.0"}) as host):
            result = probe.run("paired-instance", UDID)
        return result, host

    def good_device(self, *, process=True, listener=True):
        manifest = probe.MANIFEST.read_text()
        import json
        files = json.loads(manifest)["files"]
        return {"files": {path: {"sha256_match": True} for path in files},
                "process": process, "listener": listener,
                "trusted_cryptex_hash_match": True}

    def test_artifact_mismatch_blocks_handshake(self):
        device = self.good_device()
        next(iter(device["files"].values()))["sha256_match"] = False
        result, host = self.run_probe(device)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["reason"], "FRIDA_ARTIFACT_MISMATCH")
        host.assert_not_called()

    def test_server_down_is_degraded(self):
        result, host = self.run_probe(self.good_device(process=False, listener=False))
        self.assertEqual(result["result"], "DEGRADED")
        self.assertEqual(result["reason"], "FRIDA_SERVER_NOT_RUNNING")
        self.assertEqual(result["full_frida_uat"], "UNVERIFIED")
        host.assert_not_called()

    def test_missing_trusted_payload_explains_server_failure(self):
        device = self.good_device(process=False, listener=False)
        device["trusted_cryptex_hash_match"] = False
        result, host = self.run_probe(device)
        self.assertEqual(result["reason"], "FRIDA_TRUST_CRYPTEX_MISSING")
        host.assert_not_called()

    def test_host_version_mismatch_cannot_pass(self):
        result, _ = self.run_probe(self.good_device(),
                                   {"result": "PASS", "host_version": "17.17.0"})
        self.assertEqual(result["result"], "DEGRADED")

    def test_enumeration_pass_keeps_full_uat_unverified(self):
        result, _ = self.run_probe(self.good_device())
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["full_frida_uat"], "UNVERIFIED")

    def test_private_receipt_is_bound_and_requires_passing_probe(self):
        result, _ = self.run_probe(self.good_device())
        with tempfile.TemporaryDirectory() as folder:
            receipt = Path(folder) / "frida.json"
            probe.write_private_receipt(receipt, "SHA256:test-pinned-key", UDID, result)
            value = json.loads(receipt.read_text())
            self.assertEqual(value["device_digest"], hashlib.sha256(UDID.encode()).hexdigest())
            self.assertEqual(value["scope"], "read_only_process_enumeration")
            self.assertEqual(value["transport"], "exact_usb_iproxy")
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                probe.write_private_receipt(receipt, "SHA256:test-pinned-key", UDID,
                                            {"result": "DEGRADED"})
            self.assertEqual(json.loads(receipt.read_text()), value)


if __name__ == "__main__":
    unittest.main()
