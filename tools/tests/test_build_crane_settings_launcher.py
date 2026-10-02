from pathlib import Path
import plistlib
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import build_crane_settings_launcher as launcher


class CraneSettingsLauncherTests(unittest.TestCase):
    def test_launcher_routes_to_control_without_exiting(self):
        self.assertIn('zerosky-control://tweaks/crane', launcher.SOURCE)
        self.assertIn('Open Crane Settings', launcher.SOURCE)
        self.assertIn('UIApplicationMain', launcher.SOURCE)
        self.assertIn('applicationDidEnterBackground', launcher.SOURCE)
        self.assertNotIn('exit(', launcher.SOURCE)

    def test_adapter_preserves_upstream_identity(self):
        self.assertEqual(launcher.VERSION, "1.3.9+0sky11")
        self.assertEqual(launcher.BUILD_NUMBER, "11")
        source = Path(launcher.__file__).read_text()
        self.assertIn('com.opa334.CraneApplication', source)
        self.assertIn('original_sha256', source)
        self.assertIn('crane-settings-control-route-v1', source)

    def test_helper_service_uses_sealed_runtime_companion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            service = root / launcher.CRANE_HELPER_SERVICE
            service.parent.mkdir(parents=True)
            service.write_bytes(plistlib.dumps({
                "Label": "com.opa334.cranehelperd",
                "Program": launcher.CRANE_HELPER,
                "MachServices": {
                    "com.opa334.cranehelperd.preferences.xpc": True,
                    "com.opa334.cranehelperd.xpc": True,
                },
            }))
            launcher.adapt_helper_service(root)
            adapted = plistlib.loads(service.read_bytes())
            self.assertEqual(adapted["Program"], "/var/jb/usr/bin/python3")
            self.assertEqual(adapted["ProgramArguments"], [
                "/var/jb/usr/bin/python3", launcher.RUNTIME_MANAGER,
                "launch-companion", "com.opa334.crane", launcher.CRANE_HELPER,
            ])
            self.assertEqual(set(adapted["MachServices"]), {
                "com.opa334.cranehelperd.preferences.xpc",
                "com.opa334.cranehelperd.xpc",
            })


if __name__ == "__main__":
    unittest.main()
