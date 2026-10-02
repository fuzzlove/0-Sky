from pathlib import Path
import os
import plistlib
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))

from zero_sky_core.paths import RootlessPaths
from zero_sky_core.runtime import CoreRuntime


class CranePreMainAdapterTests(unittest.TestCase):
    bundle_id = "com.example.Converted"
    active = "A4FB34DB-8DF8-4D24-A88A-303E54E9300D"

    def runtime(self, root: Path) -> CoreRuntime:
        runtime = CoreRuntime.__new__(CoreRuntime)
        runtime.paths = RootlessPaths(root)
        return runtime

    def app(self, root: Path) -> dict:
        bundle = root / "var/containers/Bundle/Application/fixture/Converted.app"
        container = root / "var/mobile/Containers/Data/Application/fixture"
        bundle.mkdir(parents=True)
        container.mkdir(parents=True)
        (bundle / "0SkyCraneAdapter.plist").write_bytes(plistlib.dumps({
            "Schema": 1,
            "Adapter": "crane-pre-main-v1",
            "BundleIdentifier": self.bundle_id,
            "StateTransport": "private-data-handoff-v1",
            "Runtime": "embedded-reviewed-crane",
        }, fmt=plistlib.FMT_BINARY, sort_keys=True))
        return {"bundleID": self.bundle_id, "bundlePath": bundle,
                "containerPath": container}

    def write_preferences(self, root: Path) -> None:
        path = root / "var/jb/var/mobile/Library/Preferences/com.opa334.craneprefs.plist"
        path.parent.mkdir(parents=True)
        path.write_bytes(plistlib.dumps({
            "appSettings_" + self.bundle_id: {
                "Containers": [
                    {"identifier": "DEFAULT", "name": ""},
                    {"identifier": self.active, "name": "Research"},
                ],
                "activeContainer": self.active,
            },
        }))

    def test_exact_marker_is_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = self.app(root)
            self.assertEqual(CoreRuntime._crane_adapter_state(app),
                             "COMPATIBLE_WITH_ADAPTER")
            marker = app["bundlePath"] / "0SkyCraneAdapter.plist"
            value = plistlib.loads(marker.read_bytes())
            value["StateTransport"] = "unknown"
            marker.write_bytes(plistlib.dumps(value))
            self.assertEqual(CoreRuntime._crane_adapter_state(app),
                             "ADAPTATION_REQUIRED")

    def test_reconcile_writes_selected_uuid_and_removes_it_when_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = self.runtime(root)
            app = self.app(root)
            self.write_preferences(root)
            runtime._reconcile_crane_handoffs({self.bundle_id}, {self.bundle_id: app})
            handoff = app["containerPath"] / "Library/0Sky/Crane/active-container"
            self.assertEqual(handoff.read_text(), self.active + "\n")
            self.assertEqual(handoff.stat().st_mode & 0o777, 0o600)
            self.assertEqual(handoff.stat().st_uid, os.getuid())
            runtime._reconcile_crane_handoffs(set(), {self.bundle_id: app})
            self.assertFalse(handoff.exists())

    def test_fixture_uses_persistent_putenv_contract(self):
        source = (ROOT / "tools/security_test_app/main.m").read_text()
        self.assertIn("putenv(*storage)", source)
        self.assertNotIn('setenv("CRANE_CONTAINER_IDENTIFIER"', source)
        self.assertIn("Library/0Sky/Crane/active-container", source)


if __name__ == "__main__":
    unittest.main()
