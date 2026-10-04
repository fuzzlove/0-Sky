"""Release kit inventory must fail closed on portability and integrity faults."""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from tools.kit_manifest import APPROVAL_NAME, APPROVAL_STATES, REQUIRED, generate, verify
from tools.build_release import build as build_release, preflight_failure_code, remediation_for
from tools.release_paths import ReleasePaths, RuntimePaths
from tools.release_sanitize import audit
from tools.signing_identities import Identity, parse_identities, require_identity
from tools.test_offline_install import verify as verify_offline_install
from tools.wheel_inventory import write as write_wheel_inventory


def fixture(root: Path) -> None:
    for relative in sorted(set(sum(REQUIRED.values(), [])) - {"SHA256SUMS"}):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("fixture", encoding="utf-8")
    for relative in ("automation/CrypStoreAutomation/device_bridge_supervisor.sh",
                     "runtime-generation/build_and_install.sh"):
        script = root / relative
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
    wheel = root / "host-mac/wheelhouse/demo-1.0-py3-none-any.whl"
    wheel.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("demo-1.0.dist-info/METADATA",
                         "Metadata-Version: 2.3\nName: demo\nVersion: 1.0\nLicense-Expression: MIT\n")
    write_wheel_inventory(root)
    for relative in ("host-mac/zero-sky-bluetooth-tunnel",
                     "automation/CrypStoreAutomation/device_bridge_supervisor"):
        executable = root / relative
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text("fixture", encoding="utf-8")
        executable.chmod(0o755)
    (root / APPROVAL_NAME).write_text(json.dumps(
        {"schema_version": 1, "states": list(APPROVAL_STATES)}), encoding="utf-8")


class KitManifestTests(unittest.TestCase):

    def test_notary_blocker_prints_exact_credential_setup(self) -> None:
        action = remediation_for("BLOCKED_MISSING_NOTARY_PROFILE")
        self.assertIn("xcrun notarytool store-credentials", action)
        self.assertIn("--notary-profile 0-sky-release", action)

    def test_privacy_blocker_explains_each_artifact_class(self) -> None:
        action = remediation_for("EXIT_2:FIXED_HOME_PATH,PRIVATE_KEY,PERSONAL_PAYMENT")
        self.assertIn("kit_pii_report.py", action)
        self.assertIn("native or signed", action)
        self.assertIn("wheel/DEB", action)
        self.assertIn("payment/personal URLs", action)
        self.assertIn("never globally allowlist", action)

    def test_release_preflight_reports_missing_host_runtime(self) -> None:
        payload = json.dumps({"host_runtime": {"status": "BLOCKED"},
                              "kit": {"status": "PASS"},
                              "toolchain": []}).encode()
        self.assertEqual(preflight_failure_code(payload),
                         "BLOCKED_HOST_RUNTIME_MISSING_OR_INVALID")
    @unittest.skipUnless(shutil.which("zsh") and shutil.which("python3.12"),
                         "macOS offline dependency launcher unavailable")
    def test_dependency_launcher_defaults_to_offline(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = Path(__file__).resolve().parents[2] / (
                "bridge/0SkyBridge/Resources/Scripts/Install 0-Sky Dependencies.command")
            launcher = root / source.name
            launcher.write_bytes(source.read_bytes())
            (root / "macos_host_setup.py").write_text(
                "import sys; print('ARGS=' + ','.join(sys.argv[1:]))\n", encoding="utf-8")
            kit = root / "kit"
            for relative in ("SHA256SUMS", "PORTABILITY.json", "RELEASE_KIT_APPROVAL.json",
                             "RELEASE_KIT_MANIFEST.json", "WHEEL_INVENTORY.json",
                             "host-mac/HOST_RUNTIME_MANIFEST.json",
                             "host-mac/install.py", "host-mac/pair.py",
                             "host-mac/requirements-lock.txt",
                             "payloads/0-Sky-Link-1.9.0-universal.ipa"):
                item = kit / relative
                item.parent.mkdir(parents=True, exist_ok=True)
                item.write_text("fixture", encoding="utf-8")
            runtime_python = kit / "host-mac/runtime/bin/python3"
            runtime_python.parent.mkdir(parents=True)
            runtime_python.write_text(
                f"#!/bin/sh\nexec {shutil.which('python3.12')} \"$@\"\n", encoding="utf-8")
            runtime_python.chmod(0o755)
            (kit / "host-mac/wheelhouse").mkdir()
            process = subprocess.run(["/bin/zsh", str(launcher)], input="\n", text=True,
                                     capture_output=True, timeout=30, check=False)
            self.assertEqual(process.returncode, 0)
            self.assertIn("ARGS=--setup-python,--requirements-only", process.stdout)
            self.assertNotIn("--install-homebrew", process.stdout)

    def test_paths_are_independent_of_working_directory_and_home(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            project = base / "checkout"
            work = base / "work"
            project.mkdir()
            work.mkdir()
            paths = ReleasePaths.from_work(project, work)
            self.assertEqual(paths.app_bundle,
                             work.resolve() / "staging/Applications/0SkyBridge.app")
            self.assertEqual(paths.kit_root, work.resolve() / "prepared-kit")
            runtime = RuntimePaths.discover(base / "different-user")
            self.assertEqual(runtime.support_dir,
                             (base / "different-user").resolve()
                             / "Library/Application Support/0-Sky")

    def test_required_files_and_modified_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root)
            generate(root)
            self.assertEqual(verify(root), [])
            (root / "host-mac/install.py").write_text("changed", encoding="utf-8")
            self.assertIn("KIT_FILE_INVENTORY_MISMATCH", verify(root))
            (root / "host-mac/install.py").unlink()
            self.assertTrue(any("host-mac/install.py" in issue for issue in verify(root)))

    def test_external_symlink_and_unexpected_file(self) -> None:
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as elsewhere:
            root = Path(folder)
            fixture(root)
            outside = Path(elsewhere) / "external"
            outside.write_text("fixture", encoding="utf-8")
            (root / "external-link").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symlink"):
                generate(root)
            (root / "external-link").unlink()
            generate(root)
            (root / "unexpected").write_text("fixture", encoding="utf-8")
            self.assertIn("KIT_FILE_INVENTORY_MISMATCH", verify(root))

    def test_malformed_required_script_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture(root)
            (root / "host-mac/install.py").write_text("def (\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "malformed"):
                generate(root)

    def test_developer_and_volume_paths_are_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "bad.txt").write_text(
                "/" + "Users/developer/build/a\n/Volumes/build/kit/a\nDerivedData/a\nfile:///private/tmp/a",
                encoding="utf-8",
            )
            categories = {item["category"] for item in audit([root])}
            self.assertTrue({"fixed-home-path", "mounted-volume-path",
                             "derived-data-path", "absolute-file-uri"}.issubset(categories))

    def test_distribution_rejects_development_and_missing_identities(self) -> None:
        fingerprint = "A" * 40
        identities = parse_identities(f'  1) {fingerprint} "Apple Development: Example"\n')
        self.assertEqual(identities, [Identity(fingerprint, "Apple Development")])
        with self.assertRaisesRegex(RuntimeError, "BLOCKED_MISSING"):
            require_identity(fingerprint, "Developer ID Application", identities)
        with self.assertRaisesRegex(RuntimeError, "BLOCKED_MISSING"):
            require_identity(None, "Developer ID Installer", identities)

    def test_offline_install_never_uses_network_index(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "host-mac/wheelhouse").mkdir(parents=True)
            (root / "host-mac/requirements-lock.txt").write_text(
                "demo==1.0\n", encoding="utf-8")
            with patch("tools.test_offline_install.subprocess.run") as run:
                run.return_value.returncode = 0
                self.assertEqual(verify_offline_install(root, Path("/usr/bin/python3")), "PASS")
                install = run.call_args_list[1]
                argv = install.args[0]
                self.assertIn("--no-index", argv)
                self.assertIn("--isolated", argv)
                self.assertEqual(install.kwargs["env"]["PIP_NO_INDEX"], "1")
                self.assertNotIn("https://", " ".join(argv))

    def test_distribution_mode_blocks_before_build_without_developer_id(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fingerprint = "A" * 40
            with patch("tools.build_release.discover", return_value=[
                Identity(fingerprint, "Apple Development")
            ]):
                status = build_release(root / "kit", root / "dist", "distribution",
                                       fingerprint, None, None, None)
            self.assertEqual(status, 2)
            report = (root / "dist/RELEASE_AUDIT.txt").read_text(encoding="utf-8")
            self.assertIn("FINAL_RESULT=BLOCKED", report)
            self.assertIn("FIRST_FAILING_STAGE=SIGNING_PREFLIGHT", report)
            self.assertNotIn("FINAL_RESULT=PASS", report)


if __name__ == "__main__":
    unittest.main()
