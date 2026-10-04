"""Fresh-SRD release adapters stay manifest-bound and OS-version aware."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
BOOTSTRAP = ROOT / "bridge/KitScripts/srdssh/bootstrap.py"
INSTALLER = ROOT / "bridge/KitScripts/srdssh/install_cryptex_native.py"

bootstrap_spec = importlib.util.spec_from_file_location(
    "zero_sky_srdssh_bootstrap_test", BOOTSTRAP
)
bootstrap = importlib.util.module_from_spec(bootstrap_spec)
assert bootstrap_spec.loader is not None
bootstrap_spec.loader.exec_module(bootstrap)


def load_image_type_function():
    tree = ast.parse(INSTALLER.read_text(encoding="utf-8"), filename=str(INSTALLER))
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "image_type_index_for"
    )
    module = ast.Module(body=[function], type_ignores=[])
    namespace: dict[str, object] = {}
    exec(compile(module, str(INSTALLER), "exec"), namespace)
    return namespace["image_type_index_for"]


class SRDSSHReleaseAdapterTests(unittest.TestCase):
    def test_release_root_manifest_verifies_srdssh_subtree(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            kit = root / "srdssh"
            binary = kit / "payload-root/usr/bin/toybox"
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b"toybox")
            link = binary.with_name("sh")
            link.symlink_to("toybox")
            rows = []
            for relative in (
                "srdssh/payload-root/usr/bin/toybox",
                "srdssh/payload-root/usr/bin/sh",
            ):
                path = root / relative
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                rows.append(f"{digest}  ./{relative}")
            (root / "SHA256SUMS").write_text("\n".join(rows) + "\n")
            self.assertEqual(bootstrap.verify_kit_manifest(kit), 2)

    def test_manifest_rejects_escaping_link(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            kit = root / "srdssh"
            kit.mkdir()
            outside = root / "outside"
            outside.write_bytes(b"outside")
            link = kit / "escape"
            link.symlink_to("../outside")
            digest = hashlib.sha256(outside.read_bytes()).hexdigest()
            (root / "SHA256SUMS").write_text(
                f"{digest}  ./srdssh/escape\n", encoding="utf-8"
            )
            with self.assertRaisesRegex(bootstrap.ChainError, "verification failed"):
                bootstrap.verify_kit_manifest(kit)

    def test_image_slot_tracks_validated_ios_family(self):
        selector = load_image_type_function()
        self.assertEqual(selector("26.0"), 9)
        self.assertEqual(selector("26.3.1"), 9)
        self.assertEqual(selector("26.4"), 10)
        self.assertEqual(selector("27.0"), 10)
        with self.assertRaisesRegex(RuntimeError, "Unsupported SRD OS"):
            selector("25.7")

    def test_adapter_has_no_machine_specific_absolute_paths(self):
        for script in (BOOTSTRAP, INSTALLER):
            text = script.read_text(encoding="utf-8")
            self.assertNotIn("/Users/", text)
            self.assertNotIn("/Volumes/", text)


if __name__ == "__main__":
    unittest.main()
