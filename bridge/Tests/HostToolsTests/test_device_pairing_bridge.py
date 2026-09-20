import importlib.util
import base64
import hashlib
import hmac
import http.client
import json
import pathlib
import sys
import tempfile
import time
import threading
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
PATH = ROOT / "DeviceRuntime/trollstorelite-srd-bridge.py"
spec = importlib.util.spec_from_file_location("zero_sky_device_bridge_pairing_test", PATH)
bridge = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = bridge
spec.loader.exec_module(bridge)


class DevicePairingBridgeTests(unittest.TestCase):
    def test_sealed_srdssh_authorized_key_is_discovered_without_symlink_escape(self):
        root = pathlib.Path(tempfile.mkdtemp())
        mount = root / "com.liquidsky.srdssh.test/etc"
        mount.mkdir(parents=True)
        sealed = mount / "srdsh_authorized_key"
        sealed.write_text("ssh-ed25519 AAAA test\n")
        escape = root / "com.liquidsky.srdssh.escape/etc"
        escape.mkdir(parents=True)
        (escape / "srdsh_authorized_key").symlink_to(sealed)
        with mock.patch.object(bridge, "AUTHORIZED_KEYS", ("/legacy",)), \
             mock.patch.object(bridge, "SRDSH_MOUNT_ROOT", str(root)):
            paths = bridge.authorized_key_paths()
        self.assertIn("/legacy", paths)
        self.assertIn(str(sealed.resolve()), paths)
        self.assertEqual(sum(path.endswith("srdsh_authorized_key") for path in paths), 1)

    def test_worker_status_preserves_structured_pairing_evidence(self):
        root = pathlib.Path(tempfile.mkdtemp())
        heartbeat = root / "heartbeat.json"
        heartbeat.write_text(json.dumps({
            "timestamp": int(time.time()),
            "stage": "Ready", "detail": "verified", "device_udid": "device-1",
            "host_key_fingerprint": "SHA256:ssh",
            "host_name": "Research-Mac.local",
            "bridge_version": "1.0.0", "protocol_version": 1,
            "device_backend": "PymobiledeviceBackend",
            "mac_identity_fingerprint": "SHA256:mac",
            "apple_pairing_verified": True,
            "lockdown_session_validated": True,
            "host_identity_verified": True,
            "pairing_state": "VERIFIED_TRUSTED",
            "pairing_error": None,
            "device_info": {"productType": "iPad11,6"},
            "research_class": "UNKNOWN",
            "remote_services": {"status": "PASS"},
            "last_pairing_verified_at": int(time.time()),
            "transport_type": "NATIVE_REMOTEXPC",
            "wireless_connected": True,
            # A compromised or future worker must not make sensitive pairing
            # material transit through the device-facing status API.
            "EscrowBag": "must-not-forward",
            "HostPrivateKey": "must-not-forward",
        }))
        with mock.patch.object(bridge, "WORKER_HEARTBEAT", str(heartbeat)):
            status = bridge.worker_status()
        self.assertTrue(status["connected"])
        self.assertEqual(status["mac_identity_fingerprint"], "SHA256:mac")
        self.assertEqual(status["pairing_state"], "VERIFIED_TRUSTED")
        self.assertEqual(status["remote_services"]["status"], "PASS")
        self.assertEqual(status["transport_type"], "NATIVE_REMOTEXPC")
        self.assertTrue(status["wireless_connected"])
        self.assertNotIn("EscrowBag", status)
        self.assertNotIn("HostPrivateKey", status)

    def test_unenrolled_device_can_discover_nonsecret_mac_identity(self):
        root = pathlib.Path(tempfile.mkdtemp())
        missing = root / "missing-pairing.json"
        authorized = root / "authorized_keys"
        public = b"test-ed25519-public-key"
        encoded = base64.b64encode(public).decode()
        authorized.write_text(f"ssh-ed25519 {encoded} test\n")
        host_fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(public).digest()).decode().rstrip("=")
        worker = {
            "connected": True,
            "device_udid": "device-1",
            "mac_identity_fingerprint": "SHA256:public-fingerprint",
            "host_name": "Research-Mac.local",
            "bridge_version": "1.0.0",
            "protocol_version": 1,
            "pairing_state": "MAC_FOUND",
            "host_key_fingerprint": host_fingerprint,
        }
        with mock.patch.object(bridge, "PAIRING_FILE", str(missing)), \
             mock.patch.object(bridge, "AUTHORIZED_KEYS", (str(authorized),)), \
             mock.patch.object(bridge, "worker_status", return_value=worker):
            status = bridge.pairing_status()
        self.assertFalse(status["paired"])
        self.assertFalse(status["marker_valid"])
        self.assertEqual(status["mac_identity_fingerprint"], "SHA256:public-fingerprint")
        self.assertEqual(status["mac_name"], "Research-Mac.local")
        self.assertTrue(status["mac_discovery_authenticated"])
        self.assertIn("Confirm", status["message"])

    def test_discovery_never_treats_advertisement_as_trust(self):
        missing = pathlib.Path(tempfile.mkdtemp()) / "missing-pairing.json"
        worker = {"connected": True, "apple_pairing_verified": True,
                  "lockdown_session_validated": True,
                  "host_identity_verified": True,
                  "mac_identity_fingerprint": "SHA256:fp"}
        with mock.patch.object(bridge, "PAIRING_FILE", str(missing)), \
             mock.patch.object(bridge, "AUTHORIZED_KEYS", (str(missing),)), \
             mock.patch.object(bridge, "worker_status", return_value=worker):
            status = bridge.pairing_status()
        self.assertFalse(status["paired"])
        self.assertFalse(status["host_identity_verified"])
        self.assertFalse(status["mac_discovery_authenticated"])

    def test_protocol_mismatch_fails_closed_before_queueing(self):
        worker = {"connected": True, "protocol_version": 99}
        with mock.patch.object(bridge, "worker_status", return_value=worker), \
             mock.patch.object(bridge.os, "makedirs") as makedirs:
            result = bridge.queue_pair_verify()
        self.assertEqual(result["errorCode"], "PROTOCOL_VERSION_MISMATCH")
        self.assertEqual(result["expectedProtocol"], 1)
        makedirs.assert_not_called()

    def test_new_pairing_request_supersedes_abandoned_pairing_jobs(self):
        spool = pathlib.Path(tempfile.mkdtemp())
        prior_id = str(__import__("uuid").uuid4())
        prior = spool / prior_id
        prior.mkdir()
        (prior / "processing.json").write_text(json.dumps({
            "job_id": prior_id, "operation": "pair-verify",
            "created_at": int(time.time()) - 60,
        }))
        # Unrelated package jobs must not be cancelled.
        install_id = str(__import__("uuid").uuid4())
        install = spool / install_id
        install.mkdir()
        (install / "processing.json").write_text(json.dumps({
            "job_id": install_id, "operation": "install",
            "created_at": int(time.time()) - 60,
        }))
        worker = {"connected": True, "protocol_version": 1}
        with mock.patch.object(bridge, "SPOOL", str(spool)), \
             mock.patch.object(bridge, "worker_status", return_value=worker):
            queued = bridge.queue_pair_verify()
        self.assertEqual(queued["status"], 0)
        self.assertTrue((prior / "cancel.json").is_file())
        prior_result = json.loads((prior / "result.json").read_text())
        self.assertEqual(prior_result["errorCode"], "SUPERSEDED")
        self.assertFalse((install / "cancel.json").exists())
        current = spool / queued["job_id"]
        self.assertTrue((current / "request.json").is_file())

    def test_every_declared_pairing_error_has_safe_remediation(self):
        required = {
            "MAC_NOT_FOUND", "BRIDGE_NOT_RUNNING", "USB_NOT_CONNECTED",
            "MULTIPLE_DEVICES", "DEVICE_LOCKED", "TRUST_REQUIRED",
            "TRUST_DENIED", "PAIR_REQUEST_FAILED", "PAIR_RECORD_STALE",
            "LOCKDOWN_VALIDATION_FAILED", "DEVICE_IDENTITY_MISMATCH",
            "HOST_IDENTITY_MISMATCH", "REMOTE_SERVICE_UNAVAILABLE",
            "BACKEND_UNAVAILABLE", "BACKEND_VERSION_MISMATCH",
            "PROTOCOL_VERSION_MISMATCH", "TIMEOUT",
        }
        self.assertTrue(required.issubset(bridge.PAIRING_USER_MESSAGES))
        for code in required:
            message = bridge.PAIRING_USER_MESSAGES[code]
            self.assertIsInstance(message, str)
            self.assertGreater(len(message), 20)
            self.assertNotIn("Terminal", message)
            self.assertNotIn("sudo", message)

    def test_fresh_heartbeat_reaches_verified_status_without_boolean_shortcut(self):
        root = pathlib.Path(tempfile.mkdtemp())
        token_file = root / "token"
        secret = "a" * 64
        token_file.write_text(secret)
        public = b"integration-public-key"
        encoded = base64.b64encode(public).decode()
        host_key = "SHA256:" + base64.b64encode(
            hashlib.sha256(public).digest()).decode().rstrip("=")
        authorized = root / "authorized_keys"
        authorized.write_text(f"ssh-ed25519 {encoded} test\n")
        marker = {
            "schema": 1,
            "device_udid": "device-1",
            "host_key_fingerprint": host_key,
            "mac_identity_fingerprint": "SHA256:mac",
            "instance_name": "test",
        }
        canonical = json.dumps(marker, sort_keys=True, separators=(",", ":")).encode()
        marker["hmac_sha256"] = hmac.new(secret.encode(), canonical, "sha256").hexdigest()
        marker_file = root / "pairing.json"
        marker_file.write_text(json.dumps(marker))
        heartbeat = root / "heartbeat.json"
        heartbeat.write_text(json.dumps({
            "timestamp": int(time.time()), "device_udid": "device-1",
            "host_key_fingerprint": host_key, "host_name": "Research-Mac.local",
            "bridge_version": "1.0.0", "protocol_version": 1,
            "device_backend": "PymobiledeviceBackend",
            "mac_identity_fingerprint": "SHA256:mac",
            "apple_pairing_verified": True,
            "lockdown_session_validated": True,
            "host_identity_verified": True,
            "pairing_state": "VERIFIED_TRUSTED",
            "device_info": {"udid": "device-1", "productType": "iPhone13,2"},
            "research_class": "UNKNOWN", "transport_type": "USB",
        }))
        with mock.patch.object(bridge, "TOKEN_FILE", str(token_file)), \
             mock.patch.object(bridge, "PAIRING_FILE", str(marker_file)), \
             mock.patch.object(bridge, "WORKER_HEARTBEAT", str(heartbeat)), \
             mock.patch.object(bridge, "AUTHORIZED_KEYS", (str(authorized),)), \
             mock.patch.object(bridge.os, "geteuid", return_value=0):
            status = bridge.pairing_status()
        self.assertTrue(status["paired"])
        self.assertTrue(status["trusted_mac_verified"])
        self.assertTrue(status["privileged_bridge_ready"])
        self.assertTrue(status["apple_pairing_verified"])
        self.assertTrue(status["lockdown_session_validated"])
        self.assertTrue(status["host_identity_verified"])
        self.assertEqual(status["protocol_version"], 1)
        self.assertEqual(status["device_backend"], "PymobiledeviceBackend")

        # Apple/0-Sky trust must remain verified independently of the device
        # broker's privilege level. Privileged operations retain a separate
        # fail-closed gate.
        with mock.patch.object(bridge, "TOKEN_FILE", str(token_file)), \
             mock.patch.object(bridge, "PAIRING_FILE", str(marker_file)), \
             mock.patch.object(bridge, "WORKER_HEARTBEAT", str(heartbeat)), \
             mock.patch.object(bridge, "AUTHORIZED_KEYS", (str(authorized),)), \
             mock.patch.object(bridge.os, "geteuid", return_value=501):
            unprivileged = bridge.pairing_status()
        self.assertTrue(unprivileged["paired"])
        self.assertTrue(unprivileged["trusted_mac_verified"])
        self.assertFalse(unprivileged["privileged_bridge_ready"])
        with mock.patch.object(bridge, "pairing_status", return_value=unprivileged):
            denial = bridge.pairing_denial()
        self.assertEqual(denial["errorCode"], "BRIDGE_NOT_RUNNING")

    def test_multi_mac_registry_selects_live_host_without_replacing_others(self):
        root = pathlib.Path(tempfile.mkdtemp())
        token_file = root / "token"
        secret = "m" * 64
        token_file.write_text(secret)
        authorized = root / "authorized_keys"
        entries = []
        hosts = {}
        for suffix in (b"a", b"b"):
            public = suffix * 48
            encoded = base64.b64encode(public).decode()
            fingerprint = "SHA256:" + base64.b64encode(
                hashlib.sha256(public).digest()).decode().rstrip("=")
            mac = "SHA256:mac-" + suffix.decode()
            marker = {
                "schema": 1, "device_udid": "device-1",
                "host_key_fingerprint": fingerprint,
                "mac_identity_fingerprint": mac,
                "instance_name": "test-" + suffix.decode(),
            }
            identifier = bridge.pairing_host_id(marker)
            hosts[identifier] = marker
            entries.append((encoded, fingerprint, mac, identifier))
        authorized.write_text("".join(
            f"ssh-ed25519 {encoded} test\n" for encoded, *_ in entries))
        registry = {"schema": 2, "device_udid": "device-1", "hosts": hosts}
        canonical = json.dumps(registry, sort_keys=True, separators=(",", ":")).encode()
        registry["hmac_sha256"] = hmac.new(
            secret.encode(), canonical, "sha256").hexdigest()
        marker_file = root / "pairing.json"
        marker_file.write_text(json.dumps(registry))
        _, fingerprint, mac, identifier = entries[1]
        worker = {
            "connected": True, "device_udid": "device-1",
            "host_key_fingerprint": fingerprint,
            "mac_identity_fingerprint": mac,
            "protocol_version": 1, "apple_pairing_verified": True,
            "lockdown_session_validated": True, "host_identity_verified": True,
        }
        with mock.patch.object(bridge, "TOKEN_FILE", str(token_file)), \
             mock.patch.object(bridge, "PAIRING_FILE", str(marker_file)), \
             mock.patch.object(bridge, "AUTHORIZED_KEYS", (str(authorized),)), \
             mock.patch.object(bridge, "worker_status", return_value=worker), \
             mock.patch.object(bridge.os, "geteuid", return_value=0):
            status = bridge.pairing_status()
        self.assertTrue(status["paired"])
        self.assertTrue(status["pairing_registry_valid"])
        self.assertEqual(status["pairing_registry_schema"], 2)
        self.assertEqual(status["paired_host_count"], 2)
        self.assertEqual(status["active_host_id"], identifier)
        self.assertTrue(status["active_host_enrolled"])

        unknown = dict(worker, mac_identity_fingerprint="SHA256:not-enrolled")
        with mock.patch.object(bridge, "TOKEN_FILE", str(token_file)), \
             mock.patch.object(bridge, "PAIRING_FILE", str(marker_file)), \
             mock.patch.object(bridge, "AUTHORIZED_KEYS", (str(authorized),)), \
             mock.patch.object(bridge, "worker_status", return_value=unknown), \
             mock.patch.object(bridge.os, "geteuid", return_value=0):
            rejected = bridge.pairing_status()
        self.assertFalse(rejected["paired"])
        self.assertTrue(rejected["pairing_registry_valid"])
        self.assertFalse(rejected["active_host_enrolled"])
        self.assertIn("not enrolled", rejected["message"])

    def test_pairing_result_is_job_scoped_bounded_and_secret_free(self):
        spool = pathlib.Path(tempfile.mkdtemp())
        job_id = str(__import__("uuid").uuid4())
        job = spool / job_id
        job.mkdir()
        (job / "request.json").write_text("{}")
        with mock.patch.object(bridge, "SPOOL", str(spool)), \
             mock.patch.object(bridge, "pairing_status",
                               return_value={"pairing_state": "WAITING_FOR_TRUST"}):
            pending = bridge.pairing_result(job_id)
        self.assertFalse(pending["complete"])
        self.assertEqual(pending["state"], "WAITING_FOR_TRUST")

        (job / "result.json").write_text(json.dumps({
            "status": 2, "stderr": "Trust was not granted",
            "errorCode": "TRUST_DENIED",
            "EscrowBag": "never-forward",
            "HostPrivateKey": "never-forward",
            "pairing": {
                "status": "failed", "errorCode": "TRUST_DENIED",
                "userMessage": "Trust was not granted",
                "safeRemediation": "Reconnect and retry",
                "pairRecord": "never-forward",
            },
        }))
        with mock.patch.object(bridge, "SPOOL", str(spool)):
            complete = bridge.pairing_result(job_id)
        self.assertTrue(complete["complete"])
        self.assertEqual(complete["status"], 2)
        self.assertEqual(complete["result"]["errorCode"], "TRUST_DENIED")
        self.assertNotIn("EscrowBag", complete["result"])
        self.assertNotIn("HostPrivateKey", complete["result"])
        self.assertNotIn("pairRecord", complete["result"]["pairing"])

    def test_pairing_get_endpoints_reject_unauthenticated_callers(self):
        root = pathlib.Path(tempfile.mkdtemp())
        secret = "b" * 64
        token_file = root / "token"
        token_file.write_text(secret)
        spool = root / "spool"
        spool.mkdir()
        job_id = str(__import__("uuid").uuid4())
        (spool / job_id).mkdir()
        (spool / job_id / "request.json").write_text("{}")
        with mock.patch.object(bridge, "TOKEN_FILE", str(token_file)), \
             mock.patch.object(bridge, "SPOOL", str(spool)):
            server = bridge.Server(("127.0.0.1", 0), bridge.Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request("GET", f"/v1/pairing/result?job_id={job_id}")
                denied = connection.getresponse()
                self.assertEqual(denied.status, 403)
                denied.read(); connection.close()

                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request("GET", f"/v1/pairing/result?job_id={job_id}",
                                   headers={"X-TrollStore-Bridge-Token": secret})
                accepted = connection.getresponse()
                payload = json.loads(accepted.read())
                self.assertEqual(accepted.status, 200)
                self.assertFalse(payload["complete"])
                connection.close()

                body = json.dumps({"job_id": job_id})
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                connection.request("POST", "/v1/pairing/cancel", body=body,
                                   headers={"Content-Type": "application/json",
                                            "X-TrollStore-Bridge-Token": secret})
                cancelled = connection.getresponse()
                cancel_payload = json.loads(cancelled.read())
                self.assertEqual(cancelled.status, 200)
                self.assertEqual(cancel_payload["state"], "CANCELLED")
                self.assertTrue((spool / job_id / "cancel.json").is_file())
                connection.close()
            finally:
                server.shutdown(); server.server_close(); thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
