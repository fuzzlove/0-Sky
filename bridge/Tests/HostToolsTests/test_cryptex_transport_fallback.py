"""Cryptex transfer recovery changes backend once and verifies commit first."""
from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
import plistlib
import tempfile
import types
import unittest
from unittest import mock

try:
    from pymobiledevice3.exceptions import StreamClosedError
except ImportError:  # The repository's pinned device venv runs these tests.
    StreamClosedError = RuntimeError
    HAS_PYMOBILEDEVICE3 = False
else:
    HAS_PYMOBILEDEVICE3 = True


SCRIPT = (Path(__file__).resolve().parents[2] / "KitScripts/automation/"
          "CrypStoreAutomation/native-install/install_cryptex_native.py")
SPEC = importlib.util.spec_from_file_location("install_cryptex_transport_test", SCRIPT)
installer = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(installer)


class AsyncTunnel:
    def __init__(self, rsd):
        self.rsd = rsd

    async def __aenter__(self):
        return self.rsd

    async def __aexit__(self, *_args):
        return None


class CryptexImageIndexTests(unittest.TestCase):
    def test_image_type_index_tracks_verified_ios_family(self):
        self.assertEqual(installer.image_type_index_for("26.0"), 9)
        self.assertEqual(installer.image_type_index_for("26.3.1"), 9)
        self.assertEqual(installer.image_type_index_for("26.4"), 10)
        self.assertEqual(installer.image_type_index_for("27.0"), 10)
        with self.assertRaisesRegex(RuntimeError, "Unsupported SRD OS"):
            installer.image_type_index_for("25.7")


@unittest.skipUnless(HAS_PYMOBILEDEVICE3, "pinned pymobiledevice3 runtime unavailable")
class CryptexTransportFallbackTests(unittest.TestCase):
    def fixture(self, root: Path):
        info = root / "ginf"
        info.write_bytes(plistlib.dumps({"CFBundleIdentifier": "codes.example.fixture"}))
        paths = {
            "Cryptex1,CryptexInfoPlist": info,
            "Cryptex1,GenericDmg": root / "gdmg",
            "Cryptex1,GenericTrustCache": root / "gtcd",
            "Cryptex1,GenericVolume": root / "gtgv",
        }
        for path in paths.values():
            if not path.exists():
                path.write_bytes(b"fixture")
        return {}, paths

    def run_fallback(self, committed: bool):
        udid = "TEST-SRD-0001"
        native_rsd = types.SimpleNamespace(udid=udid)
        userspace_rsd = types.SimpleNamespace(udid=udid)
        installed = ([types.SimpleNamespace(identifier="codes.example.fixture")]
                     if committed else [])
        service = types.SimpleNamespace(copy_installed=mock.AsyncMock(return_value=installed))
        with tempfile.TemporaryDirectory() as folder:
            identity, paths = self.fixture(Path(folder))
            install_once = mock.AsyncMock(
                side_effect=[StreamClosedError("reset")]
                if committed else [StreamClosedError("reset"), None]
            )
            with mock.patch.object(installer, "enable_flow_control_accounting"), \
                    mock.patch.object(installer, "assets_from_manifest", return_value=(identity, paths)), \
                    mock.patch.object(installer, "install_with_rsd", install_once), \
                    mock.patch("pymobiledevice3.remote.native_tunnel.NativeRemotedTunnel",
                               return_value=AsyncTunnel(native_rsd)), \
                    mock.patch("pymobiledevice3.remote.userspace_tunnel.UserspaceRsdTunnel",
                               return_value=AsyncTunnel(userspace_rsd)) as userspace, \
                    mock.patch("pymobiledevice3.services.cryptexd.CryptexdService",
                               return_value=service):
                asyncio.run(installer.install(Path(folder) / "manifest", "codes.example.fixture", udid))
        userspace.assert_called_once_with(serial=udid, autopair=False)
        return install_once, service

    def test_uncommitted_native_reset_retries_once_on_userspace(self):
        install_once, service = self.run_fallback(committed=False)
        self.assertEqual(install_once.await_count, 2)
        service.copy_installed.assert_awaited_once()

    def test_committed_native_reset_does_not_install_twice(self):
        install_once, service = self.run_fallback(committed=True)
        self.assertEqual(install_once.await_count, 1)
        service.copy_installed.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
