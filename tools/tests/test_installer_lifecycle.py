from __future__ import annotations

import importlib.util
import hashlib
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
HOST = ROOT / "bridge/HostTools"
KIT_SCRIPTS = ROOT / "bridge/KitScripts"


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
rekey = load("fixture_rekey", KIT_SCRIPTS / "srdssh/rekey_image.py")

UDID = "00000000-0000000000000001"
OTHER = "00000000-0000000000000002"


class InstallerLifecycleTests(unittest.TestCase):
    def _kit(self, root: Path, revision: str) -> Path:
        kit = root / revision
        paths = []
        for name in installer.STAGED_DIRS:
            path = kit / name / "revision.txt"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(revision, encoding="utf-8")
            paths.append(path)
        (kit / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"./{path.relative_to(kit).as_posix()}\n"
            for path in paths
        ), encoding="utf-8")
        return kit

    def _instance_config(self, root: Path, digest: str, udid: str = UDID) -> dict:
        return {
            "schema": 2, "instance": "fixture-srd", "udid": udid,
            "ssh_host": "127.0.0.1", "ssh_port": "2222",
            "ssh_remote_port": "22", "ssh_key": str(root / "identity"),
            "source_manifest_sha256": digest,
        }

    def test_kit_revision_refresh_is_explicit_private_and_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_kit = self._kit(root, "old-kit")
            new_kit = self._kit(root, "new-kit")
            directory = root / "support/instances/fixture-srd"
            old = self._instance_config(root, "old-digest")
            new = self._instance_config(root, "new-digest")
            installer.stage_instance(old_kit, directory, old)
            (directory / "logs/preserved.log").write_text("diagnostic evidence")
            (directory / "venv").mkdir()
            (directory / "venv/runtime").write_text("managed runtime")
            (directory / "pairing-state.json").write_text("pairing material")
            (directory / ".install-complete").write_text("old-digest\n")

            with self.assertRaisesRegex(installer.InstallError, "another kit revision"):
                installer.stage_instance(new_kit, directory, new)
            self.assertEqual((directory / "host-mac/revision.txt").read_text(), "old-kit")

            checkpoint = installer.stage_instance(
                new_kit, directory, new, refresh_staged_assets=True
            )
            self.assertIsNotNone(checkpoint)
            assert checkpoint is not None
            self.assertEqual((directory / "host-mac/revision.txt").read_text(), "new-kit")
            self.assertEqual((checkpoint / "host-mac/revision.txt").read_text(), "old-kit")
            self.assertEqual((directory / "logs/preserved.log").read_text(), "diagnostic evidence")
            self.assertEqual((directory / "venv/runtime").read_text(), "managed runtime")
            self.assertEqual((directory / "pairing-state.json").read_text(), "pairing material")
            self.assertFalse((directory / ".install-complete").exists())
            self.assertEqual(checkpoint.stat().st_mode & 0o777, 0o700)
            self.assertEqual((checkpoint / "config.json").stat().st_mode & 0o777, 0o600)
            checkpoints = list((directory / "kit-refresh-backups").iterdir())
            self.assertIsNone(installer.stage_instance(
                new_kit, directory, new, refresh_staged_assets=True
            ))
            self.assertEqual(list((directory / "kit-refresh-backups").iterdir()), checkpoints)

    def test_kit_revision_refresh_refuses_endpoint_change_before_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_kit = self._kit(root, "old-kit")
            new_kit = self._kit(root, "new-kit")
            directory = root / "support/instances/fixture-srd"
            old = self._instance_config(root, "old-digest")
            installer.stage_instance(old_kit, directory, old)
            changed = self._instance_config(root, "new-digest", OTHER)
            with self.assertRaisesRegex(installer.InstallError, "another endpoint"):
                installer.stage_instance(
                    new_kit, directory, changed, refresh_staged_assets=True
                )
            self.assertEqual((directory / "host-mac/revision.txt").read_text(), "old-kit")
            self.assertFalse((directory / "kit-refresh-backups").exists())

    def test_failed_kit_revision_refresh_restores_previous_assets_and_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old_kit = self._kit(root, "old-kit")
            new_kit = self._kit(root, "new-kit")
            directory = root / "support/instances/fixture-srd"
            old = self._instance_config(root, "old-digest")
            new = self._instance_config(root, "new-digest")
            installer.stage_instance(old_kit, directory, old)
            marker = directory / ".install-complete"
            marker.write_text("old-digest\n")
            original_atomic_json = installer.atomic_json

            def fail_final_config(path, value):
                if path == directory / "config.json":
                    raise OSError("injected final config failure")
                return original_atomic_json(path, value)

            with patch.object(installer, "atomic_json", side_effect=fail_final_config):
                with self.assertRaisesRegex(OSError, "injected final config failure"):
                    installer.stage_instance(
                        new_kit, directory, new, refresh_staged_assets=True
                    )
            self.assertEqual((directory / "host-mac/revision.txt").read_text(), "old-kit")
            self.assertEqual(marker.read_text(), "old-digest\n")
            self.assertEqual(
                json.loads((directory / "config.json").read_text())["source_manifest_sha256"],
                "old-digest",
            )

    def test_device_bridge_supervisor_uses_unauthenticated_health_probe(self):
        supervisor = (HOST.parent /
                      "KitScripts/automation/CrypStoreAutomation/device_bridge_supervisor.sh")
        source = supervisor.read_text(encoding="utf-8")
        installer_source = (HOST / "install.py").read_text(encoding="utf-8")
        self.assertIn("http://127.0.0.1:48654/health", source)
        self.assertNotIn("http://127.0.0.1:48654/v1/status", source)
        # The SE's Procursus wget is killed while opening this loopback URL;
        # use the same Python runtime as the bridge for a portable probe.
        self.assertIn("/var/jb/usr/bin/python3 -c", source)
        self.assertNotIn("/var/jb/usr/bin/wget", source)
        self.assertIn('device_bridge_supervisor.sh"', installer_source)

    def test_host_helper_requires_requested_signed_architecture(self):
        with tempfile.TemporaryDirectory() as temporary:
            helper = Path(temporary) / "fixture-helper"
            helper.write_bytes(b"Mach-O fixture")
            universal = subprocess.CompletedProcess(
                ["lipo"], 0, "x86_64 arm64\n", "")
            with patch.object(installer, "run", return_value=universal) as run:
                installer.verify_helper_architecture(helper, "x86_64")
                installer.verify_helper_architecture(helper, "arm64")
            self.assertEqual(run.call_count, 4)

            arm_only = subprocess.CompletedProcess(["lipo"], 0, "arm64\n", "")
            with patch.object(installer, "run", return_value=arm_only):
                with self.assertRaisesRegex(installer.InstallError, "lacks x86_64"):
                    installer.verify_helper_architecture(helper, "x86_64")

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

    def test_release_staging_omits_python_cache_artifacts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, output = root / "kit", root / "output"
            cache = source / "host-mac/__pycache__"
            cache.mkdir(parents=True)
            files = [source / f"asset-{index}" for index in range(10)]
            files += [cache / "install.cpython-312.pyc", source / "host-mac/helper.pyo"]
            for index, path in enumerate(files):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(f"fixture {index}".encode())
            files[0].chmod(0o600)
            files[1].chmod(0o700)
            (source / "SHA256SUMS").write_text("".join(
                f"{digest(path)}  ./{path.relative_to(source).as_posix()}\n"
                for path in files))
            self.assertEqual(stage(source, output, release=True), 10)
            self.assertFalse((output / "host-mac/__pycache__").exists())
            self.assertFalse((output / "host-mac/helper.pyo").exists())
            self.assertEqual(output.stat().st_mode & 0o777, 0o755)
            self.assertEqual((output / "asset-0").stat().st_mode & 0o777, 0o644)
            self.assertEqual((output / "asset-1").stat().st_mode & 0o777, 0o755)

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
