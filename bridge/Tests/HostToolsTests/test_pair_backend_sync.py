"""Bundled worker pairing backends must match their canonical host sources."""
import ast
from pathlib import Path
import sys
import unittest


BRIDGE = Path(__file__).resolve().parents[2]
CANONICAL = BRIDGE / "HostTools"
BUNDLED = BRIDGE / "0SkyBridge/Resources/Scripts/kit/host-mac"
sys.path.insert(0, str(BRIDGE.parent))
from tools.prepare_release_kit import OVERRIDES


class PairBackendSyncTests(unittest.TestCase):
    def test_bundled_helper_matches_canonical(self):
        if not BUNDLED.is_dir():
            self.skipTest("External source kit is not present in this checkout")
        for name in ("pair.py", "apple_device_transport.py"):
            with self.subTest(name=name):
                self.assertEqual((BUNDLED / name).read_bytes(),
                                 (CANONICAL / name).read_bytes())

    def test_worker_remote_port_argument_is_supported(self):
        module = ast.parse((CANONICAL / "pair.py").read_text())
        function = next(node for node in module.body
                        if isinstance(node, ast.FunctionDef)
                        and node.name == "bind_verified_relationship")
        self.assertIn("remote_port", [arg.arg for arg in function.args.kwonlyargs])

    def test_release_overlays_canonical_pairing_backends(self):
        for name in ("pair.py", "apple_device_transport.py"):
            with self.subTest(name=name):
                self.assertEqual(OVERRIDES[f"host-mac/{name}"], CANONICAL / name)


if __name__ == "__main__":
    unittest.main()
