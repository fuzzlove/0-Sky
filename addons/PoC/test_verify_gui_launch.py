"""The device GUI probe must refuse arbitrary bundle IDs before connecting."""
import unittest

from verify_gui_launch import REMOTE, run


class GUIProbeTests(unittest.TestCase):
    def test_remote_probe_is_valid_python(self):
        compile(REMOTE, '<device-gui-probe>', 'exec')

    def test_unreviewed_app_is_rejected_before_usb_access(self):
        with self.assertRaisesRegex(ValueError, 'allowlist'):
            run('not-a-device', 'not-an-instance', 'com.example.unrelated')


if __name__ == '__main__':
    unittest.main()
