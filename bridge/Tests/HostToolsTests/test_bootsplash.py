"""Focused tests for the 0-Sky early-splash status model."""
import tempfile
import time
import unittest
from pathlib import Path

from zero_sky_core.bootsplash import (bootstrap_probe, privilege_probe,
                                     research_device_probe, runtime_probe,
                                     snapshot, ssh_probe,
                                     trust_probe)
from zero_sky_core.paths import RootlessPaths


class SplashTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        paths = RootlessPaths(root=Path(temporary.name))
        for relative in (
            "/usr/bin/python3", "/usr/bin/dpkg", "/var/lib/dpkg/status",
            "/var/lib/0sky/core.sqlite3",
            "/usr/local/libexec/trollstorelite-srd-bridge.py",
            "/usr/local/libexec/srd-runtime-manager.py",
            "/Library/LaunchDaemons/com.liquidskysecurity.trollstorelite-srd-bridge.plist",
            "/etc/trollstorelite-srd-bridge.token",
        ):
            file = paths.jailbreak(relative)
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"x")
        return paths

    def test_root_uses_effective_uid(self):
        self.assertEqual(privilege_probe(lambda: 0, lambda: 0),
                         {"root_status": "ACTIVE", "uid": 0, "euid": 0})
        self.assertEqual(privilege_probe(lambda: 501, lambda: 501)["root_status"], "INACTIVE")
        self.assertEqual(privilege_probe(lambda: 501, lambda: 0)["root_status"], "ACTIVE")

    def test_bootstrap_requires_all_indicators(self):
        paths = self.fixture()
        self.assertEqual(bootstrap_probe(paths, lambda: True)["bootstrap_status"], "ACTIVE")
        self.assertIn("runtime_manager_process",
                      bootstrap_probe(paths, lambda: False)["bootstrap_reasons"])
        paths.jailbreak("/usr/bin/dpkg").unlink()
        state = bootstrap_probe(paths, lambda: True)
        self.assertEqual(state["bootstrap_status"], "DEGRADED")
        self.assertIn("package_manager", state["bootstrap_reasons"])

    def test_trust_distinguishes_live_and_saved(self):
        self.assertEqual(trust_probe({"paired": True}), "VERIFIED")
        self.assertEqual(trust_probe({"relationship_verified": True}), "PAIRED")
        self.assertEqual(trust_probe({"pairing_registry_valid": False}), "NOT_VERIFIED")
        self.assertEqual(trust_probe(None), "UNKNOWN")
        self.assertEqual(research_device_probe({"paired": True,
                                               "research_class": "UNKNOWN"}), "UNKNOWN")
        self.assertEqual(research_device_probe({"paired": True,
                                               "research_class": "SRD"}), "AUTHORIZED_SRD")

    def test_ssh_requires_protocol_banner(self):
        pairing = {"ssh_remote_ports": [22022]}
        self.assertEqual(ssh_probe(pairing, lambda port: port == 22022), "READY")
        self.assertEqual(ssh_probe(pairing, lambda port: False), "FAILED")

    def test_runtime_and_control_reflect_existing_health(self):
        self.assertEqual(runtime_probe({"manager_active": True, "ellekit_ok": True,
                                        "crypstore_ok": True}),
                         {"runtime_status": "ACTIVE", "control_status": "ACTIVE"})
        self.assertEqual(runtime_probe({"manager_active": False, "ellekit_ok": False,
                                        "crypstore_registered": True}),
                         {"runtime_status": "FAILED", "control_status": "DEGRADED"})

    def test_timeout_and_component_exception_fail_open(self):
        paths = self.fixture()
        def slow_pairing():
            time.sleep(.15)
            return {"paired": True}
        start = time.monotonic()
        state = snapshot(slow_pairing, paths=paths, uid=lambda: 0,
                         euid=lambda: 0, banner=lambda port: False,
                         timeout_s=.01)
        self.assertLess(time.monotonic() - start, .12)
        self.assertEqual(state["trusted_host_status"], "TIMEOUT")
        self.assertEqual(state["ssh_status"], "TIMEOUT")
        def broken_pairing():
            raise RuntimeError("no pairing state")
        state = snapshot(broken_pairing, paths=paths, uid=lambda: 0,
                         euid=lambda: 0, banner=lambda port: False)
        self.assertEqual(state["trusted_host_status"], "UNKNOWN")
        self.assertEqual(state["ssh_status"], "FAILED")
        self.assertIn("trust:RuntimeError", state["diagnostics"])


if __name__ == "__main__":
    unittest.main()
