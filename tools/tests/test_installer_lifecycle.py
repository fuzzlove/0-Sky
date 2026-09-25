from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools.release_sanitize import audit
from tools.stage_verified_kit import digest, stage


ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / "bridge/0SkyBridge/Resources/Scripts/kit/host-mac"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    import sys
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


installer = load("fixture_installer", HOST / "install.py")
uninstaller = load("fixture_uninstaller", HOST / "uninstall.py")
rekey = load("fixture_rekey", HOST.parent / "srdssh/rekey_image.py")

UDID = "00000000-0000000000000001"
OTHER = "00000000-0000000000000002"


class InstallerLifecycleTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "Mach-O helper verification requires macOS")
    def test_host_helpers_have_both_signed_architectures(self):
        kit = HOST.parent
        for helper in [kit / "host-mac/zero-sky-bluetooth-tunnel",
                       kit / "automation/CrypStoreAutomation/device_bridge_supervisor"]:
            for arch in ("x86_64", "arm64"):
                installer.verify_helper_architecture(helper, arch)

    def test_ios_floor_and_future_capability_probe(self):
        for major in range(17, 29):
            self.assertEqual(installer.supported_ios_major(f"{major}.0"), major)
        with self.assertRaises(installer.InstallError):
            installer.supported_ios_major("16.7")
        with self.assertRaises(installer.InstallError):
            installer.supported_ios_major("unknown")

    def test_exact_device_uninstall_backup_and_restore(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            support = root / "support"
            agents = root / "agents"
            instance = "fixture-srd"
            directory = support / "instances" / instance
            directory.mkdir(parents=True)
            agents.mkdir()
            (directory / "config.json").write_text(json.dumps({"instance": instance, "udid": UDID}))
            (directory / "token").write_text("private fixture")
            selected = f"{uninstaller.PREFIX}worker.{instance}"
            other = f"{uninstaller.PREFIX}worker.other-srd"
            for label, device in [(selected, UDID), (other, OTHER)]:
                payload = {"Label": label, "ProgramArguments": ["/usr/bin/python3"],
                           "EnvironmentVariables": {"CRYPSTORE_DEVICE_UDID": device}}
                (agents / f"{label}.plist").write_bytes(plistlib.dumps(payload))
            planned = uninstaller.plan(instance, UDID, support, agents)
            self.assertEqual(len(planned.state), 1)
            self.assertEqual(len(planned.services), 1)
            success = subprocess.CompletedProcess(["launchctl"], 0, "state = running", "")
            with patch.object(uninstaller, "_launchctl", return_value=success):
                backup_id = uninstaller.apply_removal(planned)
                self.assertFalse(directory.exists())
                self.assertFalse((agents / f"{selected}.plist").exists())
                self.assertTrue((agents / f"{other}.plist").exists())
                self.assertEqual(uninstaller.apply_removal(
                    uninstaller.plan(instance, UDID, support, agents)), "ALREADY_REMOVED")
                uninstaller.restore(instance, UDID, support, agents, backup_id)
            self.assertTrue((directory / "config.json").exists())
            self.assertTrue((directory / "token").exists())
            self.assertTrue((agents / f"{selected}.plist").exists())
            with self.assertRaises(uninstaller.RemovalError):
                uninstaller.plan(instance, OTHER, support, agents)

    def test_uninstall_refuses_wrong_device_agent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            support, agents = root / "support", root / "agents"
            directory = support / "instances/fixture-srd"
            directory.mkdir(parents=True)
            agents.mkdir()
            (directory / "config.json").write_text(json.dumps({"udid": UDID}))
            label = f"{uninstaller.PREFIX}worker.fixture-srd"
            (agents / f"{label}.plist").write_bytes(plistlib.dumps(
                {"Label": label, "ProgramArguments": ["/usr/bin/python3"],
                 "EnvironmentVariables": {"CRYPSTORE_DEVICE_UDID": OTHER}}))
            with self.assertRaises(uninstaller.RemovalError):
                uninstaller.plan("fixture-srd", UDID, support, agents)

    def test_failed_restore_keeps_rollback_available(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            support, agents = root / "support", root / "agents"
            directory = support / "instances/fixture-srd"
            directory.mkdir(parents=True)
            agents.mkdir()
            (directory / "config.json").write_text(json.dumps({"udid": UDID}))
            label = f"{uninstaller.PREFIX}worker.fixture-srd"
            (agents / f"{label}.plist").write_bytes(plistlib.dumps(
                {"Label": label, "ProgramArguments": ["/usr/bin/python3"],
                 "EnvironmentVariables": {"CRYPSTORE_DEVICE_UDID": UDID}}))
            success = subprocess.CompletedProcess(["launchctl"], 0, "", "")
            failure = subprocess.CompletedProcess(["launchctl"], 1, "", "")
            with patch.object(uninstaller, "_launchctl", return_value=success):
                backup_id = uninstaller.apply_removal(
                    uninstaller.plan("fixture-srd", UDID, support, agents))

            def fail_bootstrap(argv):
                return failure if argv[0] == "bootstrap" else success

            with patch.object(uninstaller, "_launchctl", side_effect=fail_bootstrap):
                with self.assertRaises(uninstaller.RemovalError):
                    uninstaller.restore("fixture-srd", UDID, support, agents, backup_id)
            backup = support / "uninstall-backups" / backup_id
            self.assertTrue((backup / "state/instances/fixture-srd/config.json").exists())
            self.assertTrue((backup / "launchagents" / f"{label}.plist").exists())
            self.assertFalse(directory.exists())
            self.assertFalse((agents / f"{label}.plist").exists())
            with patch.object(uninstaller, "_launchctl", return_value=success):
                uninstaller.restore("fixture-srd", UDID, support, agents, backup_id)
            self.assertTrue((directory / "config.json").exists())

    def test_manifest_staging_omits_unlisted_private_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / "kit", root / "output"
            source.mkdir()
            for index in range(10):
                (source / f"file-{index}").write_text(f"fixture {index}")
            (source / "unlisted-private-key").write_text("private fixture")
            manifest = "".join(
                f"{digest(source / f'file-{index}')}  ./file-{index}\n"
                for index in range(10))
            (source / "SHA256SUMS").write_text(manifest)
            self.assertEqual(stage(source, output), 10)
            self.assertFalse((output / "unlisted-private-key").exists())

    def test_sanitizer_reports_categories_without_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "installer.sh"
            path.write_text('CERT_PASS="fixture-secret"\n')
            findings = audit([path])
            self.assertEqual(findings[0]["category"], "embedded-password")
            self.assertNotIn("fixture-secret", json.dumps(findings))

    def test_rekey_strips_public_key_comment(self):
        with tempfile.TemporaryDirectory() as temporary:
            key = Path(temporary) / "key.pub"
            key.write_text("ssh-ed25519 QUJDRA== person@example.invalid\n")
            self.assertEqual(rekey.public_key_text(key),
                             "ssh-ed25519 QUJDRA== 0-sky-authorized-key\n")

    def test_link_only_dry_run_preserves_runtime(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            support = root / "support"
            instance = support / "instances/fixture-srd"
            instance.mkdir(parents=True)
            pin = instance / "device-known-hosts"
            pin.write_text("fixture pin\n")
            pin.chmod(0o600)
            (instance / "config.json").write_text(json.dumps({
                "udid": UDID, "ssh_host": "127.0.0.1", "ssh_port": "2222",
                "ssh_key": str(root / "key"), "ssh_host_alias": "fixture-srd",
                "ssh_known_hosts": str(pin),
            }))
            ipa = root / "link.ipa"
            ipa.write_bytes(b"fixture IPA")
            result = subprocess.run([
                sys.executable, str(HOST / "bootstrap_device.py"),
                "--support", str(support), "--instance-name", "fixture-srd",
                "--link-only", "--zero-sky-ipa", str(ipa), "--dry-run",
            ], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("LINK_ONLY=PASS", result.stdout)
            self.assertNotIn("renewing dpkg", result.stdout)
            self.assertNotIn("package changes", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
