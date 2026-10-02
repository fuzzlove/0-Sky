import importlib.util
import pathlib
import unittest


SOURCE = pathlib.Path(__file__).resolve().parents[2] / "0SkyBridge/Resources/Scripts/afc2_root_mount.py"
SPEC = importlib.util.spec_from_file_location("afc2_root_mount", SOURCE)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class AFC2RootMountTests(unittest.TestCase):
    def test_real_root_markers_are_accepted(self):
        MODULE.verify_root_listing(["System", "private", "var", "Applications", "usr", "etc"])

    def test_media_root_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "did not expose the device root"):
            MODULE.verify_root_listing(["DCIM", "Downloads", "PhotoData"])

    def test_label_is_a_single_bounded_path_component(self):
        label = MODULE.safe_label("Joe's iPhone / SRD")
        self.assertEqual(label, "Joe-s-iPhone-SRD")
        self.assertLessEqual(len(MODULE.safe_label("x" * 200)), 64)

    def test_udid_rejects_shell_metacharacters(self):
        self.assertEqual(MODULE.validated_udid("TEST-SRD-0001"), "TEST-SRD-0001")
        with self.assertRaises(Exception):
            MODULE.validated_udid("phone; touch /tmp/no")


if __name__ == "__main__":
    unittest.main()
