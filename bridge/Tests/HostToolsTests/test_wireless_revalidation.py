"""A USB recheck must retain already verified Wi-Fi/RSD capability proof."""
import asyncio
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

HOST = Path(__file__).resolve().parents[2] / "HostTools"
sys.path.insert(0, str(HOST))
from apple_device_transport import (AppleDeviceTransportManager,
                                    TrustedDeviceRelationship)


class FakeBackend:
    async def open_lockdown(self, udid, transport):
        return SimpleNamespace(udid=udid), {
            "UniqueDeviceID": udid, "ProductType": "iPhone13,2",
            "ProductVersion": "27.0", "DeviceName": "Research Device"}

    async def set_wifi_lockdown(self, client, enabled):
        assert enabled is True

    async def get_wifi_lockdown(self, client):
        return True

    async def prepare_remote_pairing(self, client):
        return {"verified": True}

    async def close(self, client):
        pass


class WirelessRevalidationTests(unittest.TestCase):
    def check(self, prior_host, prior_wifi, prior_rsd, current_host):
        with tempfile.TemporaryDirectory(prefix="0sky-wifi-proof-") as directory:
            manager = AppleDeviceTransportManager(Path(directory), backend=FakeBackend())
            manager.registry.save_relationship(TrustedDeviceRelationship(
                deviceIdentifier="device-1", trustedMacFingerprint=prior_host,
                wifiLockdownEnabled=True, wifiPairingVerified=prior_wifi,
                wirelessRSDVerified=prior_rsd))
            result = asyncio.run(manager.enable_wireless(
                "device-1", current_host, usb_trust_verified=True))
            saved = manager.registry.load_relationship("device-1")
            return result, saved

    def test_same_host_keeps_verified_rsd_after_usb_recheck(self):
        result, saved = self.check("host-a", True, True, "host-a")
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["wirelessRSDVerified"])
        self.assertTrue(saved.wifiPairingVerified)
        self.assertTrue(saved.wirelessRSDVerified)

    def test_unverified_rsd_is_not_promoted(self):
        result, saved = self.check("host-a", True, False, "host-a")
        self.assertEqual(result["status"], "ready")
        self.assertFalse(saved.wirelessRSDVerified)

    def test_other_host_cannot_inherit_wifi_proof(self):
        result, saved = self.check("host-a", True, True, "host-b")
        self.assertEqual(result["status"], "pending")
        self.assertFalse(saved.wifiPairingVerified)
        self.assertFalse(saved.wirelessRSDVerified)


if __name__ == "__main__":
    unittest.main()
