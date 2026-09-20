import base64
import hashlib
import importlib.util
import json
import pathlib
import shlex
import sys
import tempfile
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOST = ROOT / "HostTools"
sys.path.insert(0, str(HOST))
spec = importlib.util.spec_from_file_location(
    "zero_sky_multi_host_pairing", HOST / "multi_host_pairing.py")
multi = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = multi
spec.loader.exec_module(multi)


class MultiHostPairingTests(unittest.TestCase):
    def request(self, root, udid="device-00000000000000000001", now=1000):
        mac_key = Ed25519PrivateKey.generate()
        mac_public = mac_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ssh_blob = base64.b64encode(b"s" * 48).decode()
        ssh_key = f"ssh-ed25519 {ssh_blob} test"
        body = {
            "schema": 1,
            "type": multi.REQUEST_TYPE,
            "created_at": now,
            "expires_at": now + 3600,
            "request_nonce": "a" * 32,
            "target_device_sha256": multi.target_hash(udid),
            "ssh_public_key": ssh_key,
            "ssh_key_fingerprint": multi.public_key_fingerprint(ssh_key),
            "mac_identity_public_key": base64.b64encode(mac_public).decode(),
            "mac_identity_fingerprint": "SHA256:" + base64.b64encode(
                hashlib.sha256(mac_public).digest()).decode().rstrip("="),
        }
        document = dict(body)
        document["signature"] = base64.b64encode(
            mac_key.sign(multi.canonical(body))).decode()
        path = pathlib.Path(root) / "request.json"
        path.write_text(json.dumps(document))
        return path, udid

    def test_signed_request_is_device_bound_and_tamper_evident(self):
        root = tempfile.mkdtemp()
        path, udid = self.request(root)
        value = multi.read_and_verify_request(path, udid, now=1200)
        self.assertEqual(value["type"], multi.REQUEST_TYPE)
        with self.assertRaisesRegex(RuntimeError, "selected device"):
            multi.read_and_verify_request(path, "other-device-0000000000000001", now=1200)
        tampered = json.loads(path.read_text())
        tampered["expires_at"] += 60
        path.write_text(json.dumps(tampered))
        with self.assertRaisesRegex(RuntimeError, "signature"):
            multi.read_and_verify_request(path, udid, now=1200)

    def test_approval_uses_exact_usb_pinned_ssh_and_valid_remote_program(self):
        root = pathlib.Path(tempfile.mkdtemp())
        path, udid = self.request(root, now=int(time.time()))
        identity = root / "identity"; identity.write_text("private")
        known_hosts = root / "known_hosts"; known_hosts.write_text("pin")
        completed = mock.Mock(returncode=0, stdout=json.dumps({
            "status": "authorized", "authorized_key_count": 2,
            "ssh_key_fingerprint": "SHA256:test",
        }).encode(), stderr=b"")

        def validate_remote(command, **kwargs):
            self.assertIn("StrictHostKeyChecking=yes", command)
            self.assertIn("HostKeyAlias=0sky-device-test", command)
            remote = shlex.split(command[-1])
            self.assertEqual(remote[:2], ["/var/jb/usr/bin/python3", "-c"])
            compile(remote[2], "<remote-additional-mac-authorizer>", "exec")
            body = json.loads(kwargs["input"])
            self.assertTrue(body["ssh_key_fingerprint"].startswith("SHA256:"))
            return completed

        with mock.patch.object(multi.subprocess, "run", side_effect=validate_remote):
            result = multi.approve_request(
                request=path, udid=udid, identity=identity,
                host="127.0.0.1", port=2222, known_hosts=known_hosts,
                host_alias="0sky-device-test")
        self.assertEqual(result["status"], "authorized")
        self.assertIn("additional Mac", result["next_step"])

    def test_approval_refuses_non_usb_endpoint(self):
        with self.assertRaisesRegex(RuntimeError, "exact USB"):
            multi.ssh_base("device.local", 22, pathlib.Path("/key"),
                           pathlib.Path("/pins"), "0sky-device-test")


if __name__ == "__main__":
    unittest.main()
