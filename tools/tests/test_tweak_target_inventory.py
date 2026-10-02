from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))

from zero_sky_core.snapshots import SnapshotCoordinator
from zero_sky_core.ipc import validate_request
from zero_sky_core.paths import RootlessPaths
from zero_sky_core.runtime import CoreRuntime


class TweakTargetInventoryTests(unittest.TestCase):
    def coordinator(self, root: Path) -> SnapshotCoordinator:
        return SnapshotCoordinator.__new__(SnapshotCoordinator)

    def test_registration_inventory_survives_unreadable_mcm(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            from zero_sky_core.paths import RootlessPaths
            coordinator = self.coordinator(root)
            coordinator.paths = RootlessPaths(root)
            binary = coordinator.paths.jailbreak("/usr/bin/uicache")
            binary.parent.mkdir(parents=True)
            binary.write_text("fixture")
            binary.chmod(0o755)
            output = (b"com.liquidsky.SecurityTest : "
                      b"/private/var/containers/Bundle/Application/ABC/SecurityTest.app\n")
            completed = subprocess.CompletedProcess([], 0, output, b"")
            with mock.patch("zero_sky_core.snapshots.subprocess.run",
                            return_value=completed):
                apps = coordinator.registered_apps()
            self.assertEqual(apps, [{
                "bundleID": "com.liquidsky.SecurityTest",
                "name": "SecurityTest",
                "version": "unknown",
                "bundlePathDisplay": ("/private/var/containers/Bundle/Application/"
                                      "ABC/SecurityTest.app"),
                "inventorySource": "launchservices-registration",
            }])

    def test_registration_inventory_rejects_unsafe_and_ambiguous_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            from zero_sky_core.paths import RootlessPaths
            coordinator = self.coordinator(root)
            coordinator.paths = RootlessPaths(root)
            binary = coordinator.paths.jailbreak("/usr/bin/uicache")
            binary.parent.mkdir(parents=True)
            binary.write_text("fixture")
            binary.chmod(0o755)
            output = "\n".join((
                "com.apple.Preferences : /Applications/Preferences.app",
                "org.example.escape : /private/var/containers/Bundle/Application/../Bad.app",
                "org.example.duplicate : /private/var/containers/Bundle/Application/A/One.app",
                "org.example.duplicate : /private/var/containers/Bundle/Application/B/Two.app",
                "org.example.valid : /private/var/run/com.apple.security.cryptexd/mnt/test.X/Applications/Valid.app",
            )).encode()
            completed = subprocess.CompletedProcess([], 0, output, b"")
            with mock.patch("zero_sky_core.snapshots.subprocess.run",
                            return_value=completed):
                apps = coordinator.registered_apps()
            self.assertEqual([app["bundleID"] for app in apps], ["org.example.valid"])

    def test_crane_cleanup_is_a_paired_write_operation(self):
        import time
        request = validate_request({
            "protocolVersion": 1,
            "requestId": "crane-cleanup-test",
            "timestamp": time.time(),
            "operation": "cleanupCraneContainer",
            "parameters": {
                "package": "com.opa334.crane",
                "bundleID": "com.liquidsky.SecurityTest",
                "containerID": "11111111-2222-3333-4444-555555555555",
            },
        })
        self.assertEqual(request.access, "write")

    def test_registered_bundle_path_can_prove_crane_adapter(self):
        import plistlib
        with tempfile.TemporaryDirectory() as directory:
            runtime = CoreRuntime.__new__(CoreRuntime)
            runtime.paths = RootlessPaths(Path(directory))
            display = ("/private/var/containers/Bundle/Application/"
                       "11111111-2222-3333-4444-555555555555/SecurityTest.app")
            marker = runtime.paths.system(display) / "0SkyCraneAdapter.plist"
            marker.parent.mkdir(parents=True)
            marker.write_bytes(plistlib.dumps({
                "Schema": 1,
                "Adapter": "crane-pre-main-v1",
                "BundleIdentifier": "com.liquidsky.SecurityTest",
                "StateTransport": "private-data-handoff-v1",
                "Runtime": "embedded-reviewed-crane",
            }))
            self.assertEqual(runtime._crane_adapter_state({
                "bundleID": "com.liquidsky.SecurityTest",
                "bundlePathDisplay": display,
            }, runtime.paths), "COMPATIBLE_WITH_ADAPTER")
            self.assertEqual(runtime._crane_adapter_state({
                "bundleID": "com.liquidsky.SecurityTest",
                "bundlePathDisplay": "/private/var/containers/Bundle/Application/../Bad.app",
            }), "ADAPTATION_REQUIRED")


if __name__ == "__main__":
    unittest.main()
