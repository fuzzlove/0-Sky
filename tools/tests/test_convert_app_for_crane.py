import hashlib
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

from convert_app_for_crane import BOOTSTRAP_NAME, convert


class CraneAppConverterTests(unittest.TestCase):
    def test_conversion_is_reproducible_and_structurally_verified(self):
        crane = (ROOT / ".build/crane-extract-354/var/jb/Library/"
                 "MobileSubstrate/DynamicLibraries/ Crane.dylib")
        adapters = ROOT / ".build/crane-app-adapter"
        if not crane.is_file() or not (adapters / "0SkyCraneBootstrap.dylib").is_file():
            self.skipTest("authorized paid Crane fixture is not present")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            environment = os.environ.copy()
            environment.update({
                "ZERO_SKY_TEST_APP_OUTPUT": str(work / "source"),
                "ZERO_SKY_TEST_APP_VERSION": "99.0",
            })
            subprocess.run([str(ROOT / "tools/security_test_app/build.sh")],
                           env=environment, check=True, capture_output=True, timeout=180)
            source = work / "source/0-Sky-Security-Test-99.0.ipa"
            original = hashlib.sha256(source.read_bytes()).hexdigest()
            outputs = [work / f"converted-{index}.ipa" for index in (1, 2)]
            reports = [convert(source, output, crane=crane,
                               bootstrap=adapters / "0SkyCraneBootstrap.dylib",
                               shim=adapters / "lib0SkySubstrateFunctionShim.dylib")
                       for output in outputs[:1]]
            cli_plan = subprocess.run([
                str(ROOT / "tools/0sky-convert"), str(source), "--adapter", "crane",
                "--crane-dylib", str(crane), "--adapter-directory", str(adapters),
                "--dry-run", "--explain"], check=True, capture_output=True,
                text=True, timeout=60)
            planned = __import__("json").loads(cli_plan.stdout)
            self.assertEqual(planned["compatibility"], "LIKELY_CONVERTIBLE")
            self.assertEqual(planned["transformations"][0]["rule"],
                             "crane-pre-main-app-adapter-v1")
            cli_report = work / "cli-report.json"
            subprocess.run([
                str(ROOT / "tools/0sky-convert"), str(source), "--adapter", "crane",
                "--crane-dylib", str(crane), "--adapter-directory", str(adapters),
                "--output", str(outputs[1]), "--report", str(cli_report)],
                check=True, capture_output=True, text=True, timeout=180)
            reports.append(__import__("json").loads(cli_report.read_text())["result"])
            self.assertEqual(original, hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(reports[0]["converted_sha256"],
                             reports[1]["converted_sha256"])
            with zipfile.ZipFile(outputs[0]) as archive:
                marker = plistlib.loads(archive.read(
                    "Payload/ZeroSkySecurityTest.app/0SkyCraneAdapter.plist"))
                self.assertEqual(marker["Adapter"], "crane-pre-main-v1")
                for name in ("Crane.dylib", "0SkyCraneBootstrap.dylib",
                             "lib0SkySubstrateFunctionShim.dylib"):
                    self.assertIn("Payload/ZeroSkySecurityTest.app/Frameworks/" + name,
                                  archive.namelist())
                executable = work / "ZeroSkySecurityTest"
                executable.write_bytes(archive.read(
                    "Payload/ZeroSkySecurityTest.app/ZeroSkySecurityTest"))
            linked = subprocess.run(["otool", "-L", str(executable)], check=True,
                                    capture_output=True, text=True, timeout=30).stdout
            self.assertIn(BOOTSTRAP_NAME, linked)


if __name__ == "__main__":
    unittest.main()
