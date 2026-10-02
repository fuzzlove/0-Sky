from pathlib import Path
import json
import plistlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))

from zero_sky_compat.model import Environment
from zero_sky_compat.tweak import (_dependency_available, _shape,
                                   _reviewed_crane_service, _adapt_crane_support_ios27,
                                   _sign_crane_library_ios27,
                                   adapt_verified_deb,
                                   CRANE_STARTER_ADAPTER,
                                   CRANE_IOS27_LIBCRANE_SIGNED_SHA256,
                                   REPRODUCIBLE_ARCHIVE_EPOCH)


class TweakAdmissionTests(unittest.TestCase):
    def environment(self):
        return Environment(
            ios_version="27.0", architecture="arm64", bootstrap_type="rootless",
            bootstrap_prefix="/var/jb", uid=0, gid=0,
            capabilities={"var_jb": True, "root": True,
                          "hooking_backend": "ellekit"},
            packages={"ellekit": {"version": "1.2", "installed": True}})

    def test_measured_ellekit_satisfies_legacy_substrate_name(self):
        present, adapter = _dependency_available(self.environment(), "mobilesubstrate")
        self.assertTrue(present)
        self.assertEqual(adapter, "mobilesubstrate->ellekit")

    def test_scoped_rootless_tweak_shape_is_admitted_for_runtime_testing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            location = root / "var/jb/Library/MobileSubstrate/DynamicLibraries"
            location.mkdir(parents=True)
            (location / "Fixture.dylib").write_bytes(b"fixture")
            (location / "Fixture.plist").write_bytes(plistlib.dumps({
                "Filter": {"Bundles": ["com.apple.springboard"]}}))
            (root / "DEBIAN").mkdir()
            (root / "DEBIAN/control").write_text("Package: fixture\n")
            dylibs, blockers = _shape(root)
        self.assertFalse(blockers)
        self.assertEqual(dylibs[0]["scope"],
                         {"Bundles": ["com.apple.springboard"]})

    def test_unscoped_tweak_and_maintainer_script_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            location = root / "var/jb/usr/lib/TweakInject"
            location.mkdir(parents=True)
            (location / "Fixture.dylib").write_bytes(b"fixture")
            (location / "Fixture.plist").write_bytes(plistlib.dumps({"Filter": {}}))
            control = root / "DEBIAN"
            control.mkdir()
            (control / "control").write_text("Package: fixture\n")
            (control / "postinst").write_text("#!/bin/sh\n")
            _, blockers = _shape(root)
        self.assertTrue(any("maintainer scripts" in item for item in blockers))
        self.assertTrue(any("unscoped" in item for item in blockers))

    def test_crane_service_adapter_requires_exact_program_and_xpc_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            control = root / "DEBIAN"
            control.mkdir()
            (control / "control").write_text(
                "Package: com.opa334.cranelite\nVersion: 1\nArchitecture: iphoneos-arm64\n")
            executable = root / "var/jb/usr/local/libexec/cranehelperd"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"fixture")
            executable.chmod(0o755)
            launch = root / "var/jb/Library/LaunchDaemons/com.opa334.cranehelperd.plist"
            launch.parent.mkdir(parents=True)
            launch.write_bytes(plistlib.dumps({
                "Label": "com.opa334.cranehelperd",
                "Program": "/var/jb/usr/local/libexec/cranehelperd",
                "UserName": "root", "RunAtLoad": True, "KeepAlive": True,
                "MachServices": {
                    "com.opa334.cranehelperd.xpc": True,
                    "com.opa334.cranehelperd.preferences.xpc": True,
                },
            }))
            services, blockers = _reviewed_crane_service(
                root, "com.opa334.cranelite")
            self.assertFalse(blockers)
            self.assertEqual(services[0]["label"], "com.opa334.cranehelperd")
            value = plistlib.loads(launch.read_bytes())
            value["Program"] = "/var/jb/usr/local/libexec/unreviewed"
            launch.write_bytes(plistlib.dumps(value))
            _, blockers = _reviewed_crane_service(root, "com.opa334.cranelite")
            self.assertTrue(any("differs" in item for item in blockers))

    def test_derivative_replaces_scripts_and_embeds_typed_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "source"
            control = root / "DEBIAN"
            control.mkdir(parents=True)
            (control / "control").write_text(
                "Package: com.opa334.cranelite\nVersion: 1\n"
                "Architecture: iphoneos-arm64\nMaintainer: 0-Sky Tests\n"
                "Description: fixture\n")
            scripts = []
            for name in ("postinst", "prerm", "postrm"):
                path = control / name
                path.write_text("#!/bin/sh\nexit 99\n")
                path.chmod(0o755)
                scripts.append({"name": name, "sha256": name + "-reviewed"})
            daemon = root / "var/jb/usr/local/libexec/cranehelperd"
            daemon.parent.mkdir(parents=True)
            daemon.write_bytes(b"daemon")
            daemon.chmod(0o755)
            app = root / "var/jb/Applications/Fixture.app/Info.plist"
            app.parent.mkdir(parents=True)
            app.write_bytes(plistlib.dumps({"CFBundleIdentifier": "org.example.Fixture"}))
            starter = root / "var/jb/usr/local/bin/cranehelperd_start"
            starter.parent.mkdir(parents=True)
            starter.write_bytes(b"starter")
            starter.chmod(0o755)
            service_path = root / "var/jb/Library/LaunchDaemons/com.opa334.cranehelperd.plist"
            service_path.parent.mkdir(parents=True)
            service_path.write_bytes(plistlib.dumps({"fixture": True}))
            source = base / "source.deb"
            subprocess.run(["dpkg-deb", "--build", "--root-owner-group",
                            str(root), str(source)], check=True,
                           stdout=subprocess.DEVNULL)
            service = [{"label": "com.opa334.cranehelperd",
                        "program": "/var/jb/usr/local/libexec/cranehelperd",
                        "plist": "/var/jb/Library/LaunchDaemons/com.opa334.cranehelperd.plist",
                        "mach_services": [
                            "com.opa334.cranehelperd.preferences.xpc",
                            "com.opa334.cranehelperd.xpc"]}]
            with (mock.patch("zero_sky_compat.tweak._reviewed_maintainer_adapter",
                             return_value=(scripts, [])),
                  mock.patch("zero_sky_compat.tweak._reviewed_crane_service",
                             return_value=(service, []))):
                result = adapt_verified_deb(source, base, dpkg_deb="dpkg-deb")
                second = adapt_verified_deb(source, base, dpkg_deb="dpkg-deb")
            self.assertEqual(result["adapted_sha256"], second["adapted_sha256"])
            extracted = base / "adapted"
            subprocess.run(["dpkg-deb", "--raw-extract", str(result["path"]),
                            str(extracted)], check=True, stdout=subprocess.DEVNULL)
            self.assertEqual((extracted / "DEBIAN/postinst").read_text().splitlines()[-1],
                             "exit 0")
            self.assertGreaterEqual((extracted /
                "var/jb/Applications/Fixture.app/Info.plist").stat().st_mtime,
                REPRODUCIBLE_ARCHIVE_EPOCH)
            manifest = json.loads((extracted /
                "var/jb/usr/share/0-sky/package-adapters/com.opa334.cranelite.json").read_text())
            self.assertEqual(manifest["adapter"], "crane-family-v2")
            self.assertEqual(manifest["suppressed_scripts"], scripts)
            adapted_starter = (extracted /
                "var/jb/usr/local/bin/cranehelperd_start")
            self.assertEqual(adapted_starter.read_bytes(), CRANE_STARTER_ADAPTER)
            self.assertTrue(adapted_starter.stat().st_mode & 0o100)
            self.assertNotIn(b"libjailbreak", adapted_starter.read_bytes())
            self.assertNotIn(b"launchctl", adapted_starter.read_bytes())
            self.assertEqual(manifest["compatibility_components"][0]["path"],
                "/var/jb/usr/local/bin/cranehelperd_start")
            self.assertEqual(manifest["compatibility_components"][0]["adapter"],
                "srd-service-starter-v1")
            self.assertEqual(manifest["permissions"], [{
                "path": "/var/jb/usr/local/libexec/cranehelperd",
                "uid": 0, "gid": 0, "mode": "0755"}, {
                "path": "/var/jb/usr/local/bin/cranehelperd_start",
                "uid": 0, "gid": 0, "mode": "0755"}])
            self.assertEqual(manifest["applications"], [])
            runtime = manifest["runtime"]
            self.assertEqual(runtime["required_dylibs"], [
                "/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSB.dylib",
                "/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSupport.dylib",
            ])
            self.assertEqual(
                runtime["configuration_dependent"][0]["target_source"]["key"],
                "selectedApplication")
            selectors = {item["dylib"]: item for item in runtime["process_selectors"]}
            self.assertEqual(
                selectors["/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSupport.dylib"]
                ["environment"]["XPC_SERVICE_NAME"],
                "com.apple.cfprefsd.xpc.daemon")
            self.assertEqual(
                selectors["/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSB.dylib"]
                ["executable"],
                "/System/Library/CoreServices/SpringBoard.app/SpringBoard")
            self.assertEqual(
                selectors["/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSB.dylib"]
                ["sandbox_dependencies"], [
                "/var/jb/usr/lib/libcrane.dylib",
                "/var/jb/usr/lib/libsandy.dylib",
                "/var/jb/usr/lib/libellekit.dylib",
            ])

    def test_paid_crane_uses_control_managed_explicit_allowlist(self):
        from zero_sky_compat.tweak import _crane_runtime_contract
        runtime = _crane_runtime_contract("com.opa334.crane")
        self.assertEqual(runtime["configuration_dependent"][0]["target_source"], {
            "kind": "control-app-allowlist",
            "path": ("/var/jb/var/lib/srd-runtime/tweak-targets/"
                     "com.opa334.crane.json"),
        })
        self.assertEqual(runtime["configuration_dependent"][0]["sandbox_dependencies"], [
            "/var/jb/usr/lib/libcrane.dylib",
            "/var/jb/usr/lib/libsandy.dylib",
            "/var/jb/usr/lib/libellekit.dylib",
        ])

    def test_paid_crane_patch_is_exact_and_architecture_aware(self):
        source = (ROOT / "artifacts/compatibility/intake/crane-paid-1.3.18-2/"
                  "unpacked-20260930134015/var/jb/Library/MobileSubstrate/"
                  "DynamicLibraries/CraneSupport.dylib")
        if not source.is_file():
            self.skipTest("paid Crane forensic fixture is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = (root / "var/jb/Library/MobileSubstrate/DynamicLibraries/"
                      "CraneSupport.dylib")
            output.parent.mkdir(parents=True)
            output.write_bytes(source.read_bytes())
            transformations = _adapt_crane_support_ios27(root, "com.opa334.crane")
            self.assertEqual(transformations[0]["adapter"],
                             "ios27-shared-cache-hook-v1")
            payload = output.read_bytes()
            # Fat slice offsets are also validated inside the transformer.
            self.assertEqual(payload[0x4000 + 0x9724:0x4000 + 0x9728],
                             b"\xc0\x03\x5f\xd6")
            self.assertEqual(payload[0x28000 + 0xcd5c:0x28000 + 0xcd60],
                             b"\xc0\x03\x5f\xd6")
            with self.assertRaisesRegex(ValueError, "differs"):
                _adapt_crane_support_ios27(root, "com.opa334.crane")

    def test_paid_crane_support_library_signing_is_exact(self):
        source = (ROOT / "artifacts/compatibility/intake/crane-paid-1.3.18-2/"
                  "unpacked-20260930134015/var/jb/usr/lib/libcrane.dylib")
        if not source.is_file():
            self.skipTest("paid Crane forensic fixture is unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "var/jb/usr/lib/libcrane.dylib"
            output.parent.mkdir(parents=True)
            output.write_bytes(source.read_bytes())
            transformations = _sign_crane_library_ios27(
                root, "com.opa334.crane")
            self.assertEqual(transformations[0]["adapter"],
                             "ios27-rootless-support-signing-v1")
            self.assertEqual(transformations[0]["adapted_sha256"],
                             CRANE_IOS27_LIBCRANE_SIGNED_SHA256)
            with self.assertRaisesRegex(ValueError, "differs"):
                _sign_crane_library_ios27(root, "com.opa334.crane")


if __name__ == "__main__":
    unittest.main()
