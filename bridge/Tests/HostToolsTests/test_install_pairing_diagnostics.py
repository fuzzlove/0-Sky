"""Regression coverage for actionable, private installer pairing failures."""
import importlib.util
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
PATH = ROOT / "HostTools/install.py"
SPEC = importlib.util.spec_from_file_location("zero_sky_install_diagnostics", PATH)
install = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = install
SPEC.loader.exec_module(install)


class InstallPairingDiagnosticsTests(unittest.TestCase):
    def test_pairing_failure_is_private_and_actionable(self):
        with tempfile.TemporaryDirectory() as folder:
            instance = pathlib.Path(folder)
            (instance / "logs").mkdir(mode=0o700)
            udid = "00000000-0000000000000001"
            result = subprocess.CompletedProcess(
                ["pair"], 2, "PAIRING=START\n",
                f"[0-Sky Link pairing] FAILED: USB_NOT_CONNECTED: {udid}\n",
            )
            path = install.private_transcript(instance, "pairing", result)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertIn("USB_NOT_CONNECTED", path.read_text())
            detail = install.pairing_failure_detail(result, udid)
            self.assertIn("Connect the selected SRD directly by USB", detail)
            self.assertNotIn(udid, detail)

    def test_ssh_readiness_has_exact_recovery_action(self):
        result = subprocess.CompletedProcess(
            ["pair"], 2, "",
            "[0-Sky Link pairing] FAILED: device SSH service did not provide a usable host key\n",
        )
        detail = install.pairing_failure_detail(result, "00000000-0000000000000001")
        self.assertIn("Prepare SRD/Runtime Manager", detail)

    def test_transcript_rejects_symlink_target(self):
        with tempfile.TemporaryDirectory() as folder:
            instance = pathlib.Path(folder)
            logs = instance / "logs"
            logs.mkdir()
            outside = instance / "outside"
            outside.write_text("unchanged")
            (logs / "pairing-last.log").symlink_to(outside)
            result = subprocess.CompletedProcess(["pair"], 2, "", "failed")
            with self.assertRaisesRegex(install.InstallError, "unsafe"):
                install.private_transcript(instance, "pairing", result)
            self.assertEqual(outside.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
