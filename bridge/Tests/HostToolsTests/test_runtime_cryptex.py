"""Regression tests for SRD runtime companion sealing and enrollment."""

import hashlib
import io
import importlib.util
from pathlib import Path
import plistlib
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = (Path(__file__).resolve().parents[2] /
          "KitScripts/automation/tools/"
          "srd-runtime-manager/sync_runtime_cryptex.py")
SPEC = importlib.util.spec_from_file_location("test_sync_runtime_cryptex", SCRIPT)
assert SPEC and SPEC.loader
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


class RuntimeCryptexTests(unittest.TestCase):
    @staticmethod
    def _preference_archive(bundle_name, files):
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            directory = tarfile.TarInfo(f"{bundle_name}.bundle")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
            for name, contents in files.items():
                member = tarfile.TarInfo(f"{bundle_name}.bundle/{name}")
                member.mode = 0o755 if name == bundle_name else 0o644
                member.size = len(contents)
                archive.addfile(member, io.BytesIO(contents))
        return payload.getvalue()

    def test_legacy_preference_bundle_gets_deterministic_info_plist(self):
        bundle_name = "AxonPrefs"
        executable = b"\xcf\xfa\xed\xfe" + b"legacy preference fixture"
        archive = self._preference_archive(bundle_name, {bundle_name: executable})
        completed = SimpleNamespace(returncode=0, stdout=archive, stderr=b"")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with (mock.patch.object(SYNC, "ssh", return_value=completed),
                  mock.patch.object(SYNC, "run", return_value=completed)):
                record = SYNC.copy_preference_bundle(
                    [], bundle_name, root, repair_device=False)
            info_path = root / "Library/PreferenceBundles/AxonPrefs.bundle/Info.plist"
            info = plistlib.loads(info_path.read_bytes())
            self.assertEqual(info["CFBundleExecutable"], bundle_name)
            self.assertTrue(record["synthesized_info_plist"])
            self.assertEqual(record["source_sha256"], hashlib.sha256(executable).hexdigest())
            self.assertEqual(record["info_plist_sha256"],
                             hashlib.sha256(info_path.read_bytes()).hexdigest())

    def test_legacy_preference_bundle_does_not_guess_executable(self):
        archive = self._preference_archive("AxonPrefs", {"Unexpected": b"binary"})
        completed = SimpleNamespace(returncode=0, stdout=archive, stderr=b"")
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch.object(SYNC, "ssh", return_value=completed):
                with self.assertRaisesRegex(RuntimeError, "exact legacy executable"):
                    SYNC.copy_preference_bundle(
                        [], "AxonPrefs", Path(folder), repair_device=False)

    def test_sealed_daemon_is_executable(self):
        payload = b"\xcf\xfa\xed\xfe" + b"signed daemon fixture"
        completed = SimpleNamespace(returncode=0, stdout=payload, stderr=b"")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with (mock.patch.object(SYNC, "ssh", return_value=completed),
                  mock.patch.object(SYNC, "run", return_value=completed)):
                record = SYNC.copy_companion_executable(
                    [], "/var/jb/usr/local/libexec/exampled", root)
            digest = hashlib.sha256(payload).hexdigest()
            sealed = root / "companions" / digest / "exampled"
            self.assertEqual(record["sha256"], digest)
            self.assertTrue(sealed.stat().st_mode & 0o111)

    def test_enrollment_resolves_stable_cryptex_identifier(self):
        response = SimpleNamespace(returncode=0, stdout=(
            '{"registered_path":"/private/var/containers/Bundle/Application/'
            'A/Test.app","expected_bundle_sha256":"' + "a" * 64 +
            '","expected_info_plist_hash":"' + "b" * 64 +
            '","current_mount":"/private/var/run/com.apple.security.cryptexd/'
            'mnt/org.example.test.ABC"}'), stderr="")
        with mock.patch.object(SYNC, "ssh", return_value=response) as remote:
            result = SYNC.enrolled_companion_state([], "org.example.test", "Test.app")
        self.assertIn("cryptex_identifier", remote.call_args.args[1])
        self.assertNotIn("s.get('mount'", remote.call_args.args[1])
        self.assertTrue(result["current_mount"].endswith("org.example.test.ABC"))

    def test_ios27_sandbox_adapter_does_not_mutate_existing_threads(self):
        source = (SCRIPT.parent / "sandboxed-injector/rop_inject.m").read_text()
        sandbox_fixup = source.split("bool sandboxFixup", 1)[1].split(
            "bool injectDylibViaRop", 1)[0]
        self.assertIn("callOneArgumentOnNewPthread", sandbox_fixup)
        self.assertNotIn("arbCall(", sandbox_fixup)
        self.assertIn("thread_create_running", source)

    def test_sandbox_adapter_reports_signal_termination_truthfully(self):
        source = (SCRIPT.parent / "sandboxed-injector/main.m").read_text()
        self.assertIn("Child terminated by signal", source)
        self.assertIn("WIFSIGNALED(status)", source)


if __name__ == "__main__":
    unittest.main()
