"""Ensure registrar setup distinguishes absence from transport failures."""

import contextlib
import io
import subprocess
import sys
import unittest
from unittest.mock import patch

import register_mounted_app
import setup_appregistrard


class RegistrarSetupTests(unittest.TestCase):
    def result(self, code, stdout="", stderr=""):
        return subprocess.CompletedProcess([], code, stdout, stderr)

    def test_timeout_does_not_trigger_installation(self):
        with patch.object(setup_appregistrard.subprocess, "run",
                          return_value=self.result(3, stderr="SSH timeout")) as run:
            with self.assertRaisesRegex(RuntimeError, "installation was not attempted"):
                setup_appregistrard.ensure_registrar("test", "/python", setup_appregistrard.DEFAULT_KIT)
        self.assertEqual(run.call_count, 1)

    def test_available_registrar_is_preserved(self):
        with patch.object(setup_appregistrard.subprocess, "run",
                          return_value=self.result(0, stdout="Ready")) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                setup_appregistrard.ensure_registrar("test", "/python", setup_appregistrard.DEFAULT_KIT)
        self.assertEqual(run.call_count, 1)

    def test_missing_registrar_installs_exact_build_then_rechecks(self):
        results = [self.result(2), self.result(0, '{"build":"24A437","ios":"27.0"}'),
                   self.result(0), self.result(0)]
        with patch.object(setup_appregistrard.subprocess, "run", side_effect=results) as run:
            with contextlib.redirect_stdout(io.StringIO()):
                setup_appregistrard.ensure_registrar("test", "/python", setup_appregistrard.DEFAULT_KIT)
        command = run.call_args_list[2].args[0]
        self.assertIn("research_cryptex_poc.py", command[1])
        self.assertEqual(command[command.index("--identifier") + 1], setup_appregistrard.IDENTIFIER)
        self.assertIn("24A437", command[command.index("--image") + 1])
        self.assertIn("--check-registrar", run.call_args_list[3].args[0])

    def test_mismatched_build_metadata_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "exact OS build"):
            setup_appregistrard.verified_assets(setup_appregistrard.DEFAULT_KIT, "24A437", "26.0")

    def test_timeout_is_reported_without_traceback(self):
        def timed_out(*args, **kwargs):
            raise subprocess.TimeoutExpired("ssh", 30)
        with patch.object(sys, "argv", ["register_mounted_app.py", "--udid", "test", "--check-registrar"]), \
                patch.object(register_mounted_app, "paired_ssh", return_value=timed_out), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            with self.assertRaises(SystemExit) as exited:
                register_mounted_app.main()
        self.assertEqual(exited.exception.code, 3)
        self.assertIn("could not be determined", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
