"""Release packaging rejects extra payloads and preserves exact staged bytes."""
from __future__ import annotations

from pathlib import Path
import json
import os
import plistlib
import shutil
import subprocess
import tempfile
import unittest
import zipfile

from tools.build_release import make_deny_file
from tools.kit_manifest import (APPROVAL_NAME, APPROVAL_STATES, REQUIRED,
                                generate as generate_kit_manifest)
from tools.wheel_inventory import write as write_wheel_inventory
from tools.verify_release import (
    REQUIRED_APP_SCRIPTS, package_payload, report_text,
    runtime_kit_issues, same_tree, wheel_coverage,
)


class UniversalReleaseTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("codesign") and os.uname().sysname == "Darwin",
                         "macOS codesign unavailable")
    def test_post_sign_resource_change_invalidates_app(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "Probe.app"
            (app / "Contents/MacOS").mkdir(parents=True)
            (app / "Contents/Resources").mkdir()
            (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
                "CFBundleExecutable": "Probe", "CFBundleIdentifier": "example.probe",
                "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
            }))
            executable = app / "Contents/MacOS/Probe"
            executable.write_bytes(Path("/usr/bin/true").read_bytes())
            executable.chmod(0o755)
            signed = subprocess.run(["codesign", "--force", "--sign", "-", str(app)],
                                    capture_output=True, timeout=30)
            self.assertEqual(signed.returncode, 0)
            verify = ["codesign", "--verify", "--deep", "--strict", str(app)]
            self.assertEqual(subprocess.run(verify, capture_output=True, timeout=30).returncode, 0)
            (app / "Contents/Resources/late-kit-file").write_text("changed", encoding="utf-8")
            self.assertNotEqual(subprocess.run(verify, capture_output=True, timeout=30).returncode, 0)

    def test_candidate_report_cannot_be_labeled_public_pass(self) -> None:
        report = report_text({"Product": "fixture"}, [], candidate=True)
        self.assertIn("FINAL_RESULT=BLOCKED", report)
        self.assertNotIn("FINAL_RESULT=PASS", report)

    def test_fresh_install_requires_complete_manifest_verified_kit(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "0SkyBridge.app"
            kit = app / "Contents/Resources/Kit"
            scripts = app / "Contents/Resources/Scripts"
            (kit / "host-mac/wheelhouse").mkdir(parents=True)
            scripts.mkdir(parents=True)
            for relative in REQUIRED_APP_SCRIPTS:
                (scripts / relative).write_text("fixture", encoding="utf-8")
            for relative in sorted(set(sum(REQUIRED.values(), [])) - {"SHA256SUMS"}):
                item = kit / relative
                item.parent.mkdir(parents=True, exist_ok=True)
                item.write_text("fixture", encoding="utf-8")
            for relative in ("automation/CrypStoreAutomation/device_bridge_supervisor.sh",
                             "runtime-generation/build_and_install.sh"):
                script = kit / relative
                script.parent.mkdir(parents=True, exist_ok=True)
                script.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            with zipfile.ZipFile(kit / "host-mac/wheelhouse/demo-1.0-py3-none-any.whl", "w") as archive:
                archive.writestr("demo-1.0.dist-info/METADATA",
                                 "Metadata-Version: 2.3\nName: demo\nVersion: 1.0\nLicense-Expression: MIT\n")
            write_wheel_inventory(kit)
            for relative in ("host-mac/zero-sky-bluetooth-tunnel",
                             "automation/CrypStoreAutomation/device_bridge_supervisor"):
                executable = kit / relative
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_text("fixture", encoding="utf-8")
                executable.chmod(0o755)
            (kit / APPROVAL_NAME).write_text(json.dumps(
                {"schema_version": 1, "states": list(APPROVAL_STATES)}), encoding="utf-8")
            generate_kit_manifest(kit)
            self.assertEqual(runtime_kit_issues(app), [])
            (app / "Contents/Resources/.0sky-incomplete-build").touch()
            self.assertEqual(runtime_kit_issues(app), ["INCOMPLETE_BUILD_MARKER"])
            (app / "Contents/Resources/.0sky-incomplete-build").unlink()
            (kit / "host-mac/install.py").write_text("changed", encoding="utf-8")
            self.assertIn("KIT_FILE_INVENTORY_MISMATCH", runtime_kit_issues(app))
            (kit / "host-mac/install.py").unlink()
            self.assertEqual(runtime_kit_issues(app), ["DEPENDENCY_KIT_INCOMPLETE"])

    def test_temporary_denylist_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            deny = base / "deny.json"
            make_deny_file(deny, base / "work", base / "dist")
            self.assertEqual(deny.stat().st_mode & 0o777, 0o600)
            self.assertIn("builder-home", deny.read_text(encoding="utf-8"))

    def test_wheel_lock_requires_both_architectures(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            host = Path(folder)
            (host / "requirements-lock.txt").write_text("demo==1.0\n", encoding="utf-8")
            wheelhouse = host / "wheelhouse"
            wheelhouse.mkdir()
            with zipfile.ZipFile(wheelhouse / "demo-1.0-cp312-cp312-macosx_11_0_arm64.whl", "w") as archive:
                archive.writestr("demo/__init__.py", "")
            _, issues = wheel_coverage(host)
            self.assertIn("WHEEL_MISSING:demo:x86_64", issues)
            with zipfile.ZipFile(wheelhouse / "demo-1.0-cp312-cp312-macosx_10_13_x86_64.whl", "w") as archive:
                archive.writestr("demo/__init__.py", "")
            _, issues = wheel_coverage(host)
            self.assertEqual(issues, [])

    @unittest.skipUnless(shutil.which("pkgbuild") and shutil.which("pkgutil"),
                         "macOS packaging tools unavailable")
    def test_extracted_package_must_match_allowlisted_app(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            root = base / "root"
            app = root / "Applications/0SkyBridge.app"
            app.mkdir(parents=True)
            (app / "probe.txt").write_text("expected", encoding="utf-8")
            package = base / "probe.pkg"
            command = ["pkgbuild", "--root", str(root), "--identifier",
                       "com.example.0sky.test", "--version", "1.0",
                       "--install-location", "/", str(package)]
            subprocess.run(command, check=True, capture_output=True, timeout=30)
            extracted = package_payload(package, base / "expanded")
            self.assertTrue(same_tree(app, extracted))
            (root / "unexpected.txt").write_text("extra", encoding="utf-8")
            extra_package = base / "extra.pkg"
            command[-1] = str(extra_package)
            subprocess.run(command, check=True, capture_output=True, timeout=30)
            with self.assertRaisesRegex(ValueError, "unexpected payload"):
                package_payload(extra_package, base / "expanded-extra")


if __name__ == "__main__":
    unittest.main()
