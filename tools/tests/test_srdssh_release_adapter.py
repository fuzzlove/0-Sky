"""Fresh-SRD release adapters stay manifest-bound and OS-version aware."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


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
    def test_large_userspace_install_has_one_exact_transport_retry(self):
        runtime = ROOT / "bridge/KitScripts/runtime-generation/install_cryptex_native.py"
        control = ROOT / "bridge/KitScripts/automation/CrypStoreAutomation/native-install/install_cryptex_native.py"
        self.assertEqual(runtime.read_bytes(), control.read_bytes())
        text = runtime.read_text(encoding="utf-8")
        self.assertEqual(text.count("except ProtocolError as error:"), 1)
        self.assertIn('"Timed out waiting for flow-control credit"', text)
        self.assertIn("retrying once on a fresh exact-device paired USB connection", text)
        self.assertEqual(text.count("UserspaceRsdTunnel(serial=udid, autopair=False)"), 2)

    def test_root_readiness_uses_one_authenticated_identity_session(self):
        completed = subprocess.CompletedProcess(
            ["ssh"], 0, stdout="0\nDarwin device 27.0 Toybox\n", stderr=""
        )
        with mock.patch.object(bootstrap, "ssh_call", return_value=completed) as call:
            proof = bootstrap.wait_for_root(["ssh"], timeout=1)
        self.assertIn("Darwin device", proof)
        self.assertEqual(call.call_count, 1)
        self.assertIn("uname -a", call.call_args.args[1])

    def test_personalized_payload_requires_dropbear_command_shell(self):
        text = (ROOT / "bridge/KitScripts/srdssh/rekey_image.py").read_text(
            encoding="utf-8"
        )
        self.assertIn('shell = payload / "usr/bin/sh"', text)
        self.assertIn('shell.readlink() != Path("toybox")', text)

    def test_preflight_reuses_existing_pairing_after_native_timeout(self):
        success = subprocess.CompletedProcess(
            ["python"], 0,
            stdout=(
                '{"udid":"00000000-0000000000000000","nonce_length":32,'
                '"transport":"userspace USB"}'
            ),
            stderr="",
        )
        with mock.patch.object(
            bootstrap, "run",
            side_effect=[subprocess.TimeoutExpired(["python"], 30), success],
        ) as runner:
            selected = bootstrap.remote_xpc_preflight(
                Path("python"), "00000000-0000000000000000"
            )
        self.assertEqual(selected, "userspace")
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(runner.call_args_list[0].args[0][-1], "native")
        self.assertEqual(runner.call_args_list[0].kwargs["timeout"], 30)
        self.assertEqual(runner.call_args_list[1].args[0][-1], "userspace")
        self.assertEqual(runner.call_args_list[1].kwargs["timeout"], 120)

    def test_preflight_does_not_request_userspace_when_native_is_healthy(self):
        success = subprocess.CompletedProcess(
            ["python"], 0,
            stdout=(
                '{"udid":"00000000-0000000000000000","nonce_length":32,'
                '"transport":"macOS native"}'
            ),
            stderr="",
        )
        with mock.patch.object(bootstrap, "run", return_value=success) as runner:
            selected = bootstrap.remote_xpc_preflight(
                Path("python"), "00000000-0000000000000000"
            )
        self.assertEqual(selected, "native")
        self.assertEqual(runner.call_count, 1)
        self.assertEqual(runner.call_args.args[0][-1], "native")

    def test_preflight_explains_that_existing_pairing_was_tried(self):
        failed = subprocess.CompletedProcess(
            ["python"], 1, stdout="", stderr="pairing record unavailable"
        )
        with mock.patch.object(bootstrap, "run", return_value=failed):
            with self.assertRaisesRegex(
                bootstrap.ChainError, "existing pairing record was tried"
            ):
                bootstrap.remote_xpc_preflight(
                    Path("python"), "00000000-0000000000000000"
                )

    def test_direct_cryptex_auto_prefers_userspace_on_intel_safe_path(self):
        text = INSTALLER.read_text(encoding="utf-8")
        self.assertIn(
            '"auto": (("userspace-usb", False), ("native-preferred", True))',
            text,
        )

    def test_installer_receives_the_preflight_proven_transport(self):
        inputs = {
            "image": Path("image.dmg"),
            "trust_cache": Path("trust.gtcd"),
            "volume_hash": Path("volume.hash"),
        }
        with mock.patch.object(bootstrap, "run") as runner:
            bootstrap.install_srdssh(
                Path("python"), Path("kit"), inputs,
                "00000000-0000000000000000", transport="userspace",
            )
        command = runner.call_args.args[0]
        self.assertEqual(command[command.index("--transport") + 1], "userspace")

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
