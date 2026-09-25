import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import repair_host_profile as profile


UDID = "00000000-0000000000000001"
OTHER_UDID = "00000000-0000000000000002"
INSTANCE = "iphonese-srd"


class HostProfileRepairTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.support = Path(self.temporary.name) / "0-Sky"
        self.directory = self.support / "instances" / INSTANCE
        self.directory.mkdir(parents=True)
        self.key = Path(self.temporary.name) / "srd-key"
        self.key.write_text("fixture only")
        self.key.chmod(0o600)
        self.config = self.directory / "config.json"
        self.pin = self.directory / "device-known-hosts"
        self.expected = profile.expected_config(UDID, INSTANCE, 2222, self.key.resolve(), self.support.resolve())

    def write_pin(self):
        public = base64.b64encode(b"p" * 32).decode()
        self.pin.write_text(f"{profile.alias_for(UDID)} ssh-ed25519 {public}\n")
        self.pin.chmod(0o600)

    def write_config(self, value, mode=0o600):
        self.config.write_text(json.dumps(value))
        self.config.chmod(mode)

    def test_good_profile_is_reused_without_writes(self):
        self.write_pin()
        self.write_config({**self.expected, "source_manifest_sha256": "fixture"})
        before = self.config.stat().st_mtime_ns
        self.assertEqual(profile.repair(UDID, INSTANCE, 2222, self.key, self.support, live=False), "REUSE")
        self.assertEqual(self.config.stat().st_mtime_ns, before)

    def test_transient_ssh_failure_keeps_good_profile(self):
        self.write_pin()
        self.write_config(self.expected)
        before = self.config.read_bytes()
        with patch.object(profile, "verify_live", side_effect=profile.RepairError("ERR_SSH_AUTH", "transient")):
            with self.assertRaises(profile.RepairError) as caught:
                profile.repair(UDID, INSTANCE, 2222, self.key, self.support, live=True)
        self.assertEqual(caught.exception.code, "ERR_SSH_AUTH")
        self.assertEqual(self.config.read_bytes(), before)
        self.assertEqual(list(self.directory.glob("config.invalid.*.json")), [])

    def test_missing_profile_is_created_after_live_validation(self):
        self.write_pin()
        with patch.object(profile, "verify_live") as verified:
            self.assertEqual(profile.repair(UDID, INSTANCE, 2222, self.key, self.support, live=True), "REPAIR")
            verified.assert_called_once()
        profile.validate_config(profile.read_config(self.config), self.expected)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)

    def test_partial_profile_is_quarantined_and_repaired(self):
        self.write_pin()
        self.write_config({"udid": UDID, "ssh_host": "127.0.0.1", "ssh_port": "2222", "ssh_key": self.expected["ssh_key"]}, 0o644)
        with patch.object(profile, "verify_live"):
            self.assertEqual(profile.repair(UDID, INSTANCE, 2222, self.key, self.support, live=True), "REPAIR")
        quarantined = list(self.directory.glob("config.invalid.*.json"))
        self.assertEqual(len(quarantined), 1)
        self.assertEqual(quarantined[0].stat().st_mode & 0o777, 0o600)
        profile.validate_config(profile.read_config(self.config), self.expected)

    def test_corrupt_profile_is_quarantined(self):
        self.write_pin()
        self.config.write_text("{broken")
        with patch.object(profile, "verify_live"):
            self.assertEqual(profile.repair(UDID, INSTANCE, 2222, self.key, self.support, live=True), "REPAIR")
        self.assertEqual(len(list(self.directory.glob("config.invalid.*.json"))), 1)

    def test_wrong_device_aborts_before_mutation(self):
        self.write_pin()
        self.write_config({"udid": OTHER_UDID, "ssh_port": "2222"})
        before = self.config.read_bytes()
        with patch.object(profile, "verify_live") as verified:
            with self.assertRaises(profile.RepairError) as caught:
                profile.repair(UDID, INSTANCE, 2222, self.key, self.support, live=True)
        self.assertEqual(caught.exception.code, "ERR_PROFILE_IDENTITY_MISMATCH")
        verified.assert_not_called()
        self.assertEqual(self.config.read_bytes(), before)

    def test_external_probe_has_hard_timeout(self):
        from subprocess import TimeoutExpired
        with patch.object(profile.subprocess, "run", side_effect=TimeoutExpired("probe", 1)):
            with self.assertRaises(profile.RepairError) as caught:
                profile.command(["probe"], 1)
        self.assertEqual(caught.exception.code, "ERR_PROFILE_TIMEOUT")


if __name__ == "__main__":
    unittest.main()
