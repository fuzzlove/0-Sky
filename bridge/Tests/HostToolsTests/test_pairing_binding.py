import importlib.util
import json
import hashlib
import hmac
import os
import pathlib
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOST = ROOT / "HostTools"
sys.path.insert(0, str(HOST))
spec = importlib.util.spec_from_file_location("zero_sky_pair_binding", HOST / "pair.py")
pair = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pair
spec.loader.exec_module(pair)


class FakeTransportManager:
    def __init__(self, support): self.support = support
    async def enable_wireless(self, udid, fingerprint, usb_trust_verified):
        return {"status": "ready", "wirelessTrustedTransport": "READY"}


class PairingBindingTests(unittest.TestCase):
    def pairing(self, udid="device-1"):
        return {"status": "verified", "device": {"udid": udid, "platform": "IPAD",
            "productType": "iPad11,6", "productVersion": "26.7", "buildVersion": "23H24"},
            "host": {"identityVerified": True, "publicKeyFingerprint": "SHA256:mac"},
            "pairing": {"applePairingEstablished": True, "lockdownSessionValidated": True,
                "expectedUDIDMatched": True, "transportValidated": True, "lastVerifiedAt": 1},
            "researchClass": "UNKNOWN"}

    def test_direct_binding_writes_only_verified_exact_device(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="0sky-bind-test-"))
        key = root / "key"; key.write_text("test"); os.chmod(key, 0o600)
        ready = mock.Mock(return_value=mock.Mock(stdout=b"root-bridge-ready\n"))
        with mock.patch.object(pair, "key_fingerprint", return_value="SHA256:ssh"), \
             mock.patch.object(pair, "ssh_base", return_value=["ssh"]), \
             mock.patch.object(pair, "prepare_loopback_tunnel", return_value=None), \
             mock.patch.object(pair, "ensure_device_host_key_pin",
                               return_value=["SHA256:device-host"]), \
             mock.patch.object(pair, "ssh", ready), \
             mock.patch.object(pair, "write_marker") as write_marker, \
             mock.patch.object(pair, "verify_marker") as verify_marker, \
             mock.patch.object(pair, "host_name", return_value="Research Mac"), \
             mock.patch.object(pair, "AppleDeviceTransportManager", FakeTransportManager):
            state = pair.bind_verified_relationship(
                udid="device-1", ssh_key=key, host="127.0.0.1", port="2222",
                instance_name="ipad", support=root, pairing=self.pairing())
        self.assertTrue(state["verified"])
        self.assertEqual(state["mac_identity_fingerprint"], "SHA256:mac")
        write_marker.assert_called_once()
        verify_marker.assert_called_once()
        receipt = root / "instances/ipad/pairing-state.json"
        self.assertEqual(json.loads(receipt.read_text())["device_udid"], "device-1")

    def test_device_host_key_pin_is_private_and_alias_hides_udid(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="0sky-host-pin-test-"))
        known_hosts = root / "instance/device-known-hosts"
        # A syntactically valid public key blob with enough data for the
        # parser; the test is about pin persistence, not key mathematics.
        blob = __import__("base64").b64encode(b"x" * 48).decode()
        scan = mock.Mock(returncode=0,
                         stdout=f"[127.0.0.1]:2222 ssh-ed25519 {blob}\n".encode())
        with mock.patch.object(pair, "run", return_value=scan):
            fingerprints = pair.ensure_device_host_key_pin(
                host="127.0.0.1", port="2222", udid="secret-device-id",
                known_hosts=known_hosts, allow_create=True)
        text = known_hosts.read_text()
        self.assertNotIn("secret-device-id", text)
        self.assertIn(pair.device_host_alias("secret-device-id"), text)
        self.assertEqual(known_hosts.stat().st_mode & 0o777, 0o600)
        self.assertTrue(fingerprints[0].startswith("SHA256:"))

    def test_first_host_key_pin_refuses_network_tofu(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="0sky-host-pin-test-"))
        with self.assertRaisesRegex(RuntimeError, "reconnect this device by USB"):
            pair.ensure_device_host_key_pin(
                host="device.coredevice.local", port="22", udid="device-1",
                known_hosts=root / "device-known-hosts", allow_create=True)

    def test_rotated_host_key_requires_explicit_exact_usb_repair(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="0sky-host-pin-test-"))
        known_hosts = root / "device-known-hosts"
        alias = pair.device_host_alias("device-1")
        old_blob = __import__("base64").b64encode(b"o" * 48).decode()
        new_blob = __import__("base64").b64encode(b"n" * 48).decode()
        known_hosts.write_text(
            f"{alias} ssh-ed25519 {old_blob}\n", encoding="utf-8")
        os.chmod(known_hosts, 0o600)
        scan = mock.Mock(returncode=0,
                         stdout=f"[127.0.0.1]:2222 ssh-ed25519 {new_blob}\n".encode())
        with mock.patch.object(pair, "run", return_value=scan):
            with self.assertRaisesRegex(RuntimeError, "DEVICE_HOST_KEY_MISMATCH"):
                pair.ensure_device_host_key_pin(
                    host="127.0.0.1", port="2222", udid="device-1",
                    known_hosts=known_hosts, allow_create=True)
            pair.ensure_device_host_key_pin(
                host="127.0.0.1", port="2222", udid="device-1",
                known_hosts=known_hosts, allow_create=True, allow_replace=True)
        self.assertIn(new_blob, known_hosts.read_text())
        self.assertNotIn(old_blob, known_hosts.read_text())

    def test_rotated_host_key_cannot_be_repaired_from_network(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="0sky-host-pin-test-"))
        known_hosts = root / "device-known-hosts"
        alias = pair.device_host_alias("device-1")
        blob = __import__("base64").b64encode(b"o" * 48).decode()
        known_hosts.write_text(
            f"{alias} ssh-ed25519 {blob}\n", encoding="utf-8")
        os.chmod(known_hosts, 0o600)
        # A non-loopback path returns the existing pin and never scans or
        # rotates it, even when the caller asks for repair.
        with mock.patch.object(pair, "run") as runner:
            pair.ensure_device_host_key_pin(
                host="device.local", port="22", udid="device-1",
                known_hosts=known_hosts, allow_create=True, allow_replace=True)
        runner.assert_not_called()
        self.assertIn(blob, known_hosts.read_text())

    def test_ssh_base_requires_pinned_host_key(self):
        args = pair.ssh_base("device.coredevice.local", "22", pathlib.Path("/key"),
                             known_hosts=pathlib.Path("/pins/device"),
                             host_alias="0sky-device-test")
        joined = " ".join(map(str, args))
        self.assertIn("StrictHostKeyChecking=yes", joined)
        self.assertIn('UserKnownHostsFile="/pins/device"', joined)
        self.assertIn("HostKeyAlias=0sky-device-test", joined)
        self.assertNotIn("StrictHostKeyChecking=no", joined)
        self.assertNotIn("UserKnownHostsFile=/dev/null", joined)

    def test_pairing_marker_migrates_and_preserves_multiple_macs(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="0sky-multi-mac-marker-"))
        token_path = root / "bridge.token"
        marker_path = root / "pairing.json"
        token = b"device-local-test-token"
        token_path.write_bytes(token)
        bridge_path = root / "trollstorelite-srd-bridge.py"
        bridge_path.write_text("PAIRING_REGISTRY_SCHEMA = 2\n")
        legacy = {
            "schema": 1, "device_udid": "device-1",
            "host_key_fingerprint": "SHA256:ssh-one",
            "mac_identity_fingerprint": "SHA256:mac-one",
        }
        canonical = json.dumps(legacy, sort_keys=True, separators=(",", ":")).encode()
        legacy["hmac_sha256"] = hmac.new(token, canonical, hashlib.sha256).hexdigest()
        marker_path.write_text(json.dumps(legacy))
        commands = []

        def capture(_base, command, **_kwargs):
            commands.append(command)
            return mock.Mock(stdout=b"{}")

        payloads = [
            {"schema": 1, "device_udid": "device-1",
             "host_key_fingerprint": "SHA256:ssh-two",
             "mac_identity_fingerprint": "SHA256:mac-two"},
            {"schema": 1, "device_udid": "device-1",
             "host_key_fingerprint": "SHA256:ssh-three",
             "mac_identity_fingerprint": "SHA256:mac-three"},
        ]
        for payload in payloads:
            with mock.patch.object(pair, "ssh", side_effect=capture):
                pair.write_marker(["ssh"], payload)
            remote = shlex.split(commands[-1])
            self.assertEqual(remote[:2], ["/var/jb/usr/bin/python3", "-c"])
            program = remote[2].replace(
                '"/var/jb/etc/trollstorelite-srd-bridge.token"', repr(str(token_path))
            ).replace(
                '"/var/jb/var/lib/0-sky/pairing.json"', repr(str(marker_path))
            ).replace(
                '"/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py"', repr(str(bridge_path))
            ).replace("os.chown(temporary,0,0);", "")
            completed = subprocess.run(
                [sys.executable, "-c", program], input=json.dumps(payload),
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(completed.returncode, 0, completed.stderr)

        registry = json.loads(marker_path.read_text())
        self.assertEqual(registry["schema"], 2)
        self.assertEqual(len(registry["hosts"]), 3)
        unsigned = dict(registry); supplied = unsigned.pop("hmac_sha256")
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        self.assertTrue(hmac.compare_digest(
            supplied, hmac.new(token, canonical, hashlib.sha256).hexdigest()))

    def test_identity_mismatch_fails_before_bridge_mutation(self):
        root = pathlib.Path(tempfile.mkdtemp(prefix="0sky-bind-test-"))
        key = root / "key"; key.write_text("test"); os.chmod(key, 0o600)
        with mock.patch.object(pair, "write_marker") as write_marker:
            with self.assertRaisesRegex(RuntimeError, "IDENTITY_MISMATCH"):
                pair.bind_verified_relationship(
                    udid="expected", ssh_key=key, host="127.0.0.1", port="2222",
                    instance_name=None, support=root, pairing=self.pairing("other"))
        write_marker.assert_not_called()


if __name__ == "__main__": unittest.main()
