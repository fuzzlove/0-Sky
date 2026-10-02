"""Package ownership validation before Sileo requests a Cryptex install."""
from pathlib import Path
import io
import importlib.util
import json
import plistlib
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "DeviceRuntime"))
from zero_sky_core.package_integration import PackageIntegrationError, resolve_owner


class PackageIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "Applications"
        self.root.mkdir()
        self.app = self.root / "Research.app"
        self.app.mkdir()
        (self.app / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "org.example.Research",
            "CFBundleExecutable": "Research",
        }))
        (self.app / "Research").write_bytes(b"binary")

    def test_unique_installed_package_owner(self):
        search = mock.Mock(returncode=0,
                           stdout=f"org.example.research: {self.app / 'Info.plist'}\n")
        status = mock.Mock(returncode=0, stdout="ii  ")
        with mock.patch("zero_sky_core.package_integration.subprocess.run",
                        side_effect=[search, status]) as runner:
            self.assertEqual(resolve_owner(str(self.app), root=self.root),
                             "org.example.research")
        self.assertEqual(runner.call_args_list[0].args[0][1:3],
                         ["--search", "--"])

    def test_outside_root_and_symbolic_app_rejected(self):
        with self.assertRaises(PackageIntegrationError):
            resolve_owner(str(self.root.parent / "Elsewhere.app"), root=self.root)
        symbolic = self.root / "Alias.app"
        symbolic.symlink_to(self.app, target_is_directory=True)
        with self.assertRaises(PackageIntegrationError):
            resolve_owner(str(symbolic), root=self.root)

    def test_missing_executable_rejected(self):
        (self.app / "Research").unlink()
        with self.assertRaisesRegex(PackageIntegrationError, "executable"):
            resolve_owner(str(self.app), root=self.root)

    def test_ambiguous_owner_rejected(self):
        line = str(self.app / "Info.plist")
        search = mock.Mock(returncode=0,
                           stdout=f"org.example.one: {line}\norg.example.two: {line}\n")
        with mock.patch("zero_sky_core.package_integration.subprocess.run",
                        return_value=search):
            with self.assertRaisesRegex(PackageIntegrationError, "unique"):
                resolve_owner(str(self.app), root=self.root)

    def test_partially_installed_owner_rejected(self):
        search = mock.Mock(returncode=0,
                           stdout=f"org.example.research: {self.app / 'Info.plist'}\n")
        status = mock.Mock(returncode=0, stdout="rc  ")
        with mock.patch("zero_sky_core.package_integration.subprocess.run",
                        side_effect=[search, status]):
            with self.assertRaisesRegex(PackageIntegrationError, "fully installed"):
                resolve_owner(str(self.app), root=self.root)


@unittest.skipUnless(importlib.util.find_spec("crypt"), "device Bridge needs Python crypt")
class BridgePackageCommandTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(__file__).resolve().parents[2] / "DeviceRuntime/trollstorelite-srd-bridge.py"
        spec = importlib.util.spec_from_file_location("test_srd_bridge_package", path)
        cls.bridge = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.bridge)

    def test_rejects_unprivileged_request(self):
        with mock.patch.object(self.bridge.os, "geteuid", return_value=501):
            self.assertEqual(self.bridge.integrate_package_app_cli(
                ["/var/jb/Applications/Research.app"])["status"], 126)

    def test_crane_binary_transformations_are_exact(self):
        bridge = self.bridge
        expected = [{
            "adapter": "ios27-shared-cache-hook-v1",
            "path": "/var/jb/Library/MobileSubstrate/DynamicLibraries/CraneSupport.dylib",
            "original_sha256": "91f1d8969ad16051645e8dd34c4e67b749e2b80e23a9eb83b15e79323d5ca5f1",
            "adapted_sha256": "1cbd343957156e4668510dc2bff814d37896d028fa9d4a6c0b5b8d1d84f19159",
            "change": "defer __CFPrefsGetPathForTriplet direct hook",
            "reason": ("iOS 27 rejects executable restoration of modified signed "
                       "shared-cache pages"),
        }]
        bridge.validate_crane_binary_transformations("com.opa334.crane", expected)
        bridge.validate_crane_binary_transformations("com.opa334.cranelite", [])
        altered = json.loads(json.dumps(expected))
        altered[0]["adapted_sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "reviewed contract"):
            bridge.validate_crane_binary_transformations("com.opa334.crane", altered)

    def test_crane_hidden_companion_contract_is_exact(self):
        bridge = self.bridge
        expected = [{
            "path": "/var/jb/Applications/CraneApplication.app",
            "bundle_identifier": "com.opa334.CraneApplication",
            "role": "hidden-companion",
            "launch_validation": "controlled-exit-v1",
            "original_executable_sha256": (
                "485210d727140983493be0b7fc9cbcc724b8c696dc5becd86af9d6b2bb5289e6"
            ),
        }]
        bridge.validate_crane_applications("com.opa334.crane", expected)
        bridge.validate_crane_applications("com.opa334.cranelite", [])
        altered = [dict(expected[0], role="foreground-app")]
        with self.assertRaisesRegex(RuntimeError, "lifecycle contract"):
            bridge.validate_crane_applications("com.opa334.crane", altered)

    def test_rejects_mixed_runtime_package(self):
        bridge = self.bridge
        target = "/var/jb/Applications/Research.app"
        payload = {"apps": [str(Path(target).resolve())],
                   "tweaks": ["/var/jb/usr/lib/TweakInject/X.dylib"],
                   "preferences": [], "daemons": []}
        with (mock.patch.object(bridge.os, "geteuid", return_value=0),
              mock.patch.object(bridge, "resolve_owner", return_value="org.example.research"),
              mock.patch.object(bridge, "pairing_denial", return_value=None),
              mock.patch.object(bridge, "package_payload", return_value=payload),
              mock.patch.object(bridge, "integration_report") as integrate):
            result = bridge.integrate_package_app_cli([target])
        self.assertEqual(result["status"], 192)
        integrate.assert_not_called()

    def test_integrates_only_verified_owned_app(self):
        bridge = self.bridge
        target = "/var/jb/Applications/Research.app"
        payload = {"apps": [str(Path(target).resolve())], "tweaks": [],
                   "preferences": [], "daemons": []}
        with (mock.patch.object(bridge.os, "geteuid", return_value=0),
              mock.patch.object(bridge, "resolve_owner", return_value="org.example.research"),
              mock.patch.object(bridge, "pairing_denial", return_value=None),
              mock.patch.object(bridge, "package_payload", return_value=payload),
              mock.patch.object(bridge, "integration_report",
                                return_value=(payload, ["registered"], [])) as integrate):
            result = bridge.integrate_package_app_cli([target])
        self.assertEqual(result["status"], 0)
        integrate.assert_called_once_with("org.example.research",
                                          app_filter=str(Path(target).resolve()))

    def test_exact_existing_app_integration_is_idempotent(self):
        bridge = self.bridge
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "Research.app"
            registered = root / "registered" / "Research.app"
            mount = root / "mount"
            mounted_app = mount / "Applications" / "Research.app"
            state_root = root / "state"
            for app in (source, registered, mounted_app):
                app.mkdir(parents=True)
                (app / "Info.plist").write_bytes(plistlib.dumps({
                    "CFBundleIdentifier": "org.example.Research",
                    "CFBundleExecutable": "Research",
                }))
                (app / "Research").write_bytes(b"signed binary")
            state_root.mkdir()
            info_hash = bridge.hashlib.sha256(
                (registered / "Info.plist").read_bytes()).hexdigest()
            (state_root / "org.example.Research.json").write_text(json.dumps({
                "bundle_id": "org.example.Research",
                "source_sha256": "a" * 64,
                "registered_path": str(registered),
                "mount": str(mount),
                "expected_info_plist_hash": info_hash,
                "expected_bundle_sha256": bridge._bundle_tree_sha256(registered),
                "foreground_launch": "REQUIRED",
            }))
            real_lstat = bridge.pathlib.Path.lstat

            def root_owned_lstat(path):
                value = real_lstat(path)
                if path == state_root / "org.example.Research.json":
                    return mock.Mock(st_mode=stat.S_IFREG | 0o600, st_uid=0,
                                     st_size=value.st_size)
                return value

            with (mock.patch.object(bridge, "registered_bundle_path",
                                    return_value=(True, str(registered))),
                  mock.patch.object(bridge.os.path, "ismount", return_value=True),
                  mock.patch.object(bridge.pathlib.Path, "lstat", root_owned_lstat)):
                result = bridge.verified_existing_app_integration(
                    str(source), "a" * 64, state_root=str(state_root),
                    mount_root=str(root))
            self.assertEqual(result["status"], 0)
            self.assertTrue(result["already_integrated"])

    def test_existing_app_integration_rejects_different_artifact(self):
        bridge = self.bridge
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "Research.app"
            source.mkdir()
            (source / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "org.example.Research",
                "CFBundleExecutable": "Research",
            }))
            self.assertIsNone(bridge.verified_existing_app_integration(
                str(source), "b" * 64, state_root=str(Path(directory) / "missing")))

    def test_ephemeral_loader_is_not_required_to_remain_running(self):
        bridge = self.bridge
        payload = {"apps": [], "tweaks": ["/var/jb/usr/lib/TweakInject/X.dylib"],
                   "preferences": [], "daemons": []}
        processes = mock.Mock(returncode=0,
                              stdout=b"392 /var/jb/usr/bin/python3 /var/jb/usr/local/libexec/srd-runtime-manager.py daemon\n",
                              stderr=b"")
        sync = mock.Mock(returncode=0, stdout=b"rescan requested", stderr=b"")
        with (mock.patch.object(bridge, "package_payload", return_value=payload),
              mock.patch.object(bridge.os.path, "isfile", return_value=True),
              mock.patch.object(bridge.subprocess, "run", side_effect=[processes, sync])):
            _, messages, failures = bridge.integration_report("org.example.tweak")
        self.assertEqual(failures, [])
        self.assertTrue(any("controlled runtime probe" in item for item in messages))

    def test_runtime_validation_never_passes_with_unregistered_required_dylib(self):
        bridge = self.bridge
        required = "/var/jb/Library/MobileSubstrate/DynamicLibraries/Required.dylib"
        payload = {"tweaks": [required], "adapters": []}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(bridge, "RUNTIME_STATE_DIR", directory), \
                mock.patch.object(bridge, "package_adapter_manifest", return_value=None):
            Path(directory, "registry.json").write_text(json.dumps({"targets": {}}))
            Path(directory, "injection-state.json").write_text(json.dumps({"loaded": {}}))
            result = bridge.tweak_runtime_validation("org.example.tweak", payload, timeout=0)
        self.assertEqual(result["result"], "FAIL")
        self.assertEqual(result["missing_required"], [str(Path(required).resolve())])

    def test_crane_app_hook_is_configuration_required_until_app_selected(self):
        bridge = self.bridge
        root = "/var/jb/Library/MobileSubstrate/DynamicLibraries"
        sb, support, app = (root + "/CraneSB.dylib", root + "/CraneSupport.dylib",
                            root + "/ Crane.dylib")
        contract = {"runtime": {
            "required_dylibs": [sb, support],
            "configuration_dependent": [{
                "dylib": app, "legacy_filter": "com.apple.Foundation",
                "target_source": {"kind": "plist-string",
                                  "path": "/missing/preferences.plist",
                                  "key": "selectedApplication"},
            }],
        }}
        registry = {"targets": {
            "/SpringBoard": {"name": "com.apple.springboard", "dylibs": [
                {"package": "com.opa334.cranelite", "path": sb, "sha256": "a"}]},
            "/usr/sbin/cfprefsd": {"name": "cfprefsd", "dylibs": [
                {"package": "com.opa334.cranelite", "path": support,
                 "sha256": "b"}]},
        }}
        state = {"loaded": {
            "one": {"target": "com.apple.springboard", "dylib": sb,
                    "sha256": "a", "pid": 100},
            "two": {"target": "cfprefsd", "dylib": support,
                    "sha256": "b", "pid": 101},
        }}
        payload = {"tweaks": [sb, support, app], "adapters": ["manifest"]}
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(bridge, "RUNTIME_STATE_DIR", directory), \
                mock.patch.object(bridge, "package_adapter_manifest", return_value=contract), \
                mock.patch.object(bridge.os, "kill"):
            Path(directory, "registry.json").write_text(json.dumps(registry))
            Path(directory, "injection-state.json").write_text(json.dumps(state))
            result = bridge.tweak_runtime_validation(
                "com.opa334.cranelite", payload, timeout=0)
        self.assertEqual(result["result"], "CONFIGURATION_REQUIRED")
        self.assertEqual(result["configuration_dependent"], [str(Path(app).resolve())])

    def test_missing_runtime_manager_is_pending_until_post_install_sync(self):
        bridge = self.bridge
        payload = {"apps": [], "tweaks": ["/var/jb/usr/lib/TweakInject/X.dylib"],
                   "preferences": [], "daemons": []}
        processes = mock.Mock(returncode=0, stdout=b"1 /sbin/launchd\n", stderr=b"")
        with (mock.patch.object(bridge, "package_payload", return_value=payload),
              mock.patch.object(bridge.os.path, "isfile", return_value=False),
              mock.patch.object(bridge.subprocess, "run", return_value=processes)):
            _, messages, failures = bridge.integration_report("org.example.tweak")
        self.assertEqual(failures, [])
        self.assertTrue(any("activation is pending" in item for item in messages))

    def test_sileo_removal_requires_exact_plan_and_verifies_absence(self):
        bridge = self.bridge
        request = {"operation": "remove", "packages":
                   [{"id": "com.example.tweak", "version": "1.0"}]}
        payload = {"apps": [], "tweaks": ["/var/jb/usr/lib/TweakInject/Test.dylib"],
                   "preferences": [], "daemons": []}
        with (mock.patch.object(bridge, "installed_package_versions",
                                side_effect=[{"com.example.tweak": "1.0"}, {}]),
              mock.patch.object(bridge, "package_payload", return_value=payload),
              mock.patch.object(bridge.sileo_package_service, "execute",
                                return_value={"status": 0, "result": "PLAN_READY"}) as plan,
              mock.patch.object(bridge.sileo_package_service,
                                "installed_status_snapshot", return_value=b"Package: base\n") as snapshot,
              mock.patch.object(bridge, "remove_tweak_package",
                                return_value={"status": 0,
                                    "preference_runtime_refresh": {"status": 0}}) as remove):
            result = bridge.sileo_package_operation(request)
        self.assertEqual(result["result"], "REMOVED_AND_VERIFIED")
        self.assertEqual(plan.call_args.args[0]["operation"], "plan-remove")
        remove.assert_called_once_with("com.example.tweak", expected_version="1.0")
        snapshot.assert_called_once_with()
        self.assertEqual(result["installed_status_b64"], "UGFja2FnZTogYmFzZQo=")

    def test_remove_tweak_refreshes_runtime_with_exact_package_id(self):
        bridge = self.bridge
        package = "com.example.tweak"
        payload = {"apps": [],
                   "tweaks": ["/var/jb/usr/lib/TweakInject/Test.dylib"],
                   "preferences": [], "daemons": []}
        removed = mock.Mock(returncode=0, stdout=b"removed\n", stderr=b"")
        with (mock.patch.object(bridge, "installed_package_versions",
                                return_value={package: "1.0"}),
              mock.patch.object(bridge, "package_payload", return_value=payload),
              mock.patch.object(bridge.subprocess, "run", return_value=removed),
              mock.patch.object(bridge, "preference_repair",
                                return_value={"changed": False,
                                              "summary": "no changes"}),
              mock.patch.object(bridge, "queue_runtime_sync",
                                return_value={"status": 0,
                                              "stdout": "trusted"}) as sync):
            result = bridge.remove_tweak_package(package, expected_version="1.0")
        self.assertEqual(result["status"], 0)
        sync.assert_called_once_with(package)

    def test_sileo_install_returns_status_snapshot_before_reporting_completion(self):
        bridge = self.bridge
        request = {"operation": "install", "packages":
                   [{"id": "org.example.utility", "version": "1.0"}]}
        payload = {"apps": [], "tweaks": [], "preferences": [], "daemons": []}
        with (mock.patch.object(bridge, "worker_status", return_value={"connected": True}),
              mock.patch.object(bridge, "installed_package_versions",
                                side_effect=[{}, {"org.example.utility": "1.0"}]),
              mock.patch.object(bridge.sileo_package_service, "execute",
                                return_value={"status": 0, "result": "INSTALL_REQUIRES_VERIFICATION"}),
              mock.patch.object(bridge.subprocess, "run",
                                return_value=mock.Mock(returncode=0, stdout=b"", stderr=b"")),
              mock.patch.object(bridge, "integration_report",
                                return_value=(payload, [], [])),
              mock.patch.object(bridge, "queue_runtime_sync",
                                return_value={"status": 0, "stdout": "trusted"}) as sync,
              mock.patch.object(bridge.sileo_package_service,
                                "installed_status_snapshot",
                                return_value=b"Package: org.example.utility\n") as snapshot):
            result = bridge.sileo_package_operation(request)
        self.assertEqual(result["result"], "INSTALLED_UNVERIFIED")
        self.assertEqual(result["changed_packages"], ["org.example.utility"])
        sync.assert_called_once_with("org.example.utility")
        snapshot.assert_called_once_with()
        self.assertIn("installed_status_b64", result)

    def test_sileo_http_reports_unexpected_preflight_failure_instead_of_status_190(self):
        bridge = self.bridge
        body = json.dumps({"operation": "install", "packages": [{
            "id": "com.example.tweak", "version": "1.0",
            "archive": "a" * 64 + ".deb",
        }]}).encode()
        handler = object.__new__(bridge.Handler)
        handler.path = "/v1/sileo/package"
        handler.headers = {"X-0Sky-Sileo-Token": "test-token",
                           "Content-Length": str(len(body))}
        handler.rfile = io.BytesIO(body)
        handler.server = mock.Mock(token="unused")
        handler.reply = mock.Mock(side_effect=lambda code, payload: (code, payload))
        with (tempfile.TemporaryDirectory() as directory,
              mock.patch.object(bridge, "LOG", str(Path(directory) / "bridge.log")),
              mock.patch.object(bridge.sileo_package_service, "authenticated",
                                return_value=True),
              mock.patch.object(bridge, "pairing_denial", return_value=None),
              mock.patch.object(bridge, "sileo_package_operation",
                                side_effect=RuntimeError("private diagnostic")),
              mock.patch.object(bridge.traceback, "print_exc")):
            code, payload = handler.do_POST()
            log = json.loads((Path(directory) / "bridge.log").read_text())
        self.assertEqual(code, 500)
        self.assertEqual(payload["status"], 192)
        self.assertEqual(payload["stage"], "PACKAGE_OPERATION")
        self.assertEqual(payload["error_code"], "RuntimeError")
        self.assertNotIn("private diagnostic", payload["stderr"])
        self.assertEqual(log["status"], 192)
        self.assertEqual(log["error_detail"], "private diagnostic")

    def test_sileo_error_detail_redacts_credentials_and_host_user(self):
        value = self.bridge.sanitized_error_detail(RuntimeError(
            "token=abc password: xyz https://me:pw@example.test /Users/person/build"))
        self.assertNotIn("abc", value)
        self.assertNotIn("xyz", value)
        self.assertNotIn("me:pw", value)
        self.assertNotIn("person", value)

    def test_sileo_install_reports_status_snapshot_failure(self):
        bridge = self.bridge
        request = {"operation": "install", "packages":
                   [{"id": "org.example.utility", "version": "1.0"}]}
        payload = {"apps": [], "tweaks": [], "preferences": [], "daemons": []}
        with (mock.patch.object(bridge, "worker_status", return_value={"connected": True}),
              mock.patch.object(bridge, "installed_package_versions",
                                side_effect=[{}, {"org.example.utility": "1.0"}]),
              mock.patch.object(bridge.sileo_package_service, "execute",
                                return_value={"status": 0, "result": "INSTALL_REQUIRES_VERIFICATION"}),
              mock.patch.object(bridge.subprocess, "run",
                                return_value=mock.Mock(returncode=0, stdout=b"", stderr=b"")),
              mock.patch.object(bridge, "integration_report",
                                return_value=(payload, [], [])),
              mock.patch.object(bridge, "queue_runtime_sync",
                                return_value={"status": 0, "stdout": "trusted"}),
              mock.patch.object(bridge.sileo_package_service,
                                "installed_status_snapshot",
                                side_effect=bridge.sileo_package_service.SileoRequestError(
                                    "unsafe package view"))):
            result = bridge.sileo_package_operation(request)
        self.assertEqual(result["result"], "REPAIR_REQUIRED")
        self.assertEqual(result["stage"], "STATUS_SNAPSHOT")
        self.assertEqual(result["status"], 192)

    def test_failed_tweak_install_refreshes_rollback_with_exact_package_id(self):
        bridge = self.bridge
        package = "com.example.tweak"
        request = {"operation": "install", "packages":
                   [{"id": package, "version": "1.0"}]}
        payload = {"apps": [],
                   "tweaks": ["/var/jb/usr/lib/TweakInject/Test.dylib"],
                   "preferences": [], "daemons": [], "adapters": []}
        apt_check = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        removed = mock.Mock(returncode=0, stdout=b"", stderr=b"")
        with (mock.patch.object(bridge, "worker_status", return_value={"connected": True}),
              mock.patch.object(bridge, "installed_package_versions",
                                side_effect=[{}, {package: "1.0"}, {}]),
              mock.patch.object(bridge.sileo_package_service, "execute",
                                return_value={"status": 0,
                                              "result": "INSTALL_REQUIRES_VERIFICATION"}),
              mock.patch.object(bridge.subprocess, "run",
                                side_effect=[apt_check, removed]),
              mock.patch.object(bridge, "integration_report",
                                return_value=(payload, [], ["runtime failed"])),
              mock.patch.object(bridge, "record_compatibility_runtime",
                                return_value={}),
              mock.patch.object(bridge, "deactivate_package_adapter"),
              mock.patch.object(bridge, "queue_runtime_sync",
                                return_value={"status": 0, "stdout": "trusted"}) as sync):
            result = bridge.sileo_package_operation(request)
        self.assertEqual(result["result"], "REPAIR_REQUIRED")
        self.assertTrue(result["rollback_verified"])
        self.assertEqual(result["rollback_runtime_sync"]["status"], 0)
        sync.assert_called_once_with(package)

    def test_runtime_sync_waits_for_post_install_worker_heartbeat(self):
        bridge = self.bridge
        with (tempfile.TemporaryDirectory() as directory,
              mock.patch.object(bridge, "SPOOL", directory),
              mock.patch.object(bridge, "worker_status", side_effect=[
                  {"connected": False}, {"connected": False},
                  {"connected": True}]) as status,
              mock.patch.object(bridge.time, "sleep"),
              mock.patch.object(bridge.time, "monotonic",
                                side_effect=[0, 0, 1, 1, 2, 2, 3]),
              mock.patch.object(bridge, "atomic_json") as write):
            # Stop after proving the job is admitted; no Mac worker is present
            # in this isolated unit test to produce a result file.
            with mock.patch.object(bridge.os.path, "isfile", side_effect=RuntimeError("queued")):
                with self.assertRaisesRegex(RuntimeError, "queued"):
                    bridge.queue_runtime_sync("com.example.tweak")
        self.assertEqual(status.call_count, 3)
        self.assertEqual(write.call_args.args[1]["package"], "com.example.tweak")

    def test_sileo_removal_does_not_run_after_blocked_plan(self):
        bridge = self.bridge
        request = {"operation": "remove", "packages":
                   [{"id": "com.example.tweak", "version": "1.0"}]}
        payload = {"apps": [], "tweaks": ["/var/jb/usr/lib/TweakInject/Test.dylib"],
                   "preferences": [], "daemons": []}
        with (mock.patch.object(bridge, "installed_package_versions",
                                return_value={"com.example.tweak": "1.0"}),
              mock.patch.object(bridge, "package_payload", return_value=payload),
              mock.patch.object(bridge.sileo_package_service, "execute",
                                return_value={"status": 193, "result": "BLOCKED"}),
              mock.patch.object(bridge, "remove_tweak_package") as remove):
            result = bridge.sileo_package_operation(request)
        self.assertEqual(result["result"], "BLOCKED")
        remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
