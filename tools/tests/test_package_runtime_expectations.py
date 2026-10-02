import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))

from zero_sky_core.paths import RootlessPaths
from zero_sky_core.sensors.recovery import PackageInventory


class PackageRuntimeExpectationTests(unittest.TestCase):
    def fixture(self, root: Path, manifest: dict | None) -> PackageInventory:
        paths = RootlessPaths(root)
        status = paths.jailbreak("/Library/dpkg/status")
        status.parent.mkdir(parents=True)
        status.write_text(
            "Package: com.example.adapter\n"
            "Status: install ok installed\n"
            "Version: 1.0\n"
            "Architecture: iphoneos-arm64\n\n")
        info = paths.jailbreak("/Library/dpkg/info")
        info.mkdir(parents=True)
        (info / "com.example.adapter.list").write_text("/var/jb/test\n")
        state = paths.jailbreak("/var/lib/srd-runtime")
        state.mkdir(parents=True)
        tweaks = [
            {"package": "com.example.adapter", "dylib": f"/var/jb/lib/{name}",
             "sha256": name + "-sha"}
            for name in ("required-a.dylib", "required-b.dylib", "conditional.dylib")
        ]
        (state / "registry.json").write_text(json.dumps({"tweaks": tweaks}))
        (state / "injection-state.json").write_text(json.dumps({"loaded": {
            "a": tweaks[0], "b": tweaks[1],
        }}))
        if manifest is not None:
            adapters = paths.jailbreak("/usr/share/0-sky/package-adapters")
            adapters.mkdir(parents=True)
            (adapters / "com.example.adapter.json").write_text(json.dumps(manifest))
        return PackageInventory(paths)

    def test_reviewed_adapter_excludes_configuration_dependent_dylib(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = self.fixture(Path(directory), {
                "package": "com.example.adapter",
                "runtime": {
                    "required_dylibs": [
                        "/var/jb/lib/required-a.dylib",
                        "/var/jb/lib/required-b.dylib",
                    ],
                    "configuration_dependent": [{
                        "dylib": "/var/jb/lib/conditional.dylib",
                    }],
                },
            })
            row = inventory.collect()[0]
            self.assertEqual(row["runtimeState"], "PASS")
            self.assertEqual(row["runtimeExpectedCount"], 2)
            self.assertEqual(row["runtimeLoadedCount"], 2)
            self.assertEqual(row["runtimeConditionalCount"], 1)

    def test_invalid_adapter_fails_closed_to_discovered_dylibs(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = self.fixture(Path(directory), {
                "package": "com.example.adapter",
                "runtime": {"required_dylibs": ["relative/path.dylib"]},
            })
            row = inventory.collect()[0]
            self.assertEqual(row["runtimeState"], "DEGRADED")
            self.assertEqual(row["runtimeExpectedCount"], 3)
            self.assertEqual(row["runtimeLoadedCount"], 2)
            self.assertEqual(row["runtimeConditionalCount"], 0)


if __name__ == "__main__":
    unittest.main()
