"""One-shot startup trigger must be bounded, configurable and fail-open."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

from zero_sky_core.paths import RootlessPaths

SOURCE = Path(__file__).resolve().parents[3] / "bridge/DeviceRuntime/bootsplash_launch.py"
spec = importlib.util.spec_from_file_location("bootsplash_launch_test", SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class LauncherTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        paths = RootlessPaths(root=Path(temporary.name))
        uiopen = paths.jailbreak("/usr/bin/uiopen")
        uiopen.parent.mkdir(parents=True, exist_ok=True)
        uiopen.write_bytes(b"x")
        uiopen.chmod(0o755)
        return paths

    def test_disabled_never_opens(self):
        paths = self.fixture()
        config = paths.jailbreak("/etc/0sky-bootsplash.json")
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text('{"bootsplash":{"enabled":false}}')
        result = module.launch(paths, springboard=lambda: True,
                               opener=lambda: self.fail("must not open"))
        self.assertEqual(result["status"], "DISABLED")

    def test_waits_for_springboard_and_opens_once(self):
        paths = self.fixture()
        ready = iter([False, False, True])
        calls = []
        now = [0.0]
        def clock(): return now[0]
        def sleep(seconds): now[0] += seconds
        def open_app(): calls.append(1); return True
        result = module.launch(paths, springboard=lambda: next(ready),
                               opener=open_app, now=clock, sleep=sleep)
        self.assertEqual(result["status"], "OPENED")
        self.assertEqual(calls, [1])

    def test_open_failure_is_bounded_and_does_not_loop(self):
        paths = self.fixture()
        now = [0.0]
        result = module.launch(paths, springboard=lambda: True,
            opener=lambda: False, now=lambda: now[0],
            sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["attempts"], 3)

    def test_springboard_timeout_does_not_open(self):
        paths = self.fixture()
        now = [0.0]
        result = module.launch(paths, springboard=lambda: False,
            opener=lambda: self.fail("must not open"), now=lambda: now[0],
            sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))
        self.assertEqual(result["status"], "SPRINGBOARD_TIMEOUT")
        self.assertEqual(result["duration_ms"], 30000)

    def test_claim_runs_once_per_kernel_boot(self):
        paths = self.fixture()
        self.assertTrue(module.claim_once(paths, 100))
        self.assertFalse(module.claim_once(paths, 100))
        self.assertTrue(module.claim_once(paths, 101))


if __name__ == "__main__":
    unittest.main()
