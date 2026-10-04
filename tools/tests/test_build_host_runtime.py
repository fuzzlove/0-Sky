"""Pinned host-runtime assembly reports exact offline recovery actions."""
from __future__ import annotations

from pathlib import Path
import importlib.util
import io
import socket
import tarfile
import tempfile
import threading
import unittest

from tools import build_host_runtime


class BuildHostRuntimeTests(unittest.TestCase):
    def test_offline_missing_archive_names_url_path_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "python.tar.gz"
            with self.assertRaises(build_host_runtime.RuntimeBuildError) as caught:
                build_host_runtime.download(
                    "https://example.invalid/python.tar.gz", "a" * 64,
                    destination, offline=True,
                )
        action = caught.exception.remediation
        self.assertIn("https://example.invalid/python.tar.gz", action)
        self.assertIn(str(destination), action)
        self.assertIn("shasum -a 256", action)
        self.assertIn("a" * 64, action)

    def test_dpkg_extractor_rejects_symlink_parent_escape(self) -> None:
        module_path = Path(__file__).resolve().parents[2] / "bridge/HostRuntime/dpkg_deb.py"
        specification = importlib.util.spec_from_file_location("zero_sky_dpkg", module_path)
        assert specification and specification.loader
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            outside = root / "outside"
            outside.mkdir()
            archive = io.BytesIO()
            with tarfile.open(fileobj=archive, mode="w") as bundle:
                link = tarfile.TarInfo("escape")
                link.type = tarfile.SYMTYPE
                link.linkname = str(outside)
                bundle.addfile(link)
                contents = b"must-not-escape"
                item = tarfile.TarInfo("escape/written")
                item.size = len(contents)
                bundle.addfile(item, io.BytesIO(contents))
            with self.assertRaises(RuntimeError):
                module.extract_archive(archive.getvalue(), root / "destination")
            self.assertFalse((outside / "written").exists())

    def test_dpkg_reader_rejects_oversized_package_before_reading(self) -> None:
        module_path = Path(__file__).resolve().parents[2] / "bridge/HostRuntime/dpkg_deb.py"
        specification = importlib.util.spec_from_file_location("zero_sky_dpkg_size", module_path)
        assert specification and specification.loader
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            package = Path(folder) / "oversized.deb"
            with package.open("wb") as stream:
                stream.truncate(module.MAX_PACKAGE_SIZE + 1)
            with self.assertRaisesRegex(ValueError, "1 GiB"):
                module.members(package)

    def test_usbmux_relay_handles_backpressure_without_sendall(self) -> None:
        module_path = Path(__file__).resolve().parents[2] / "bridge/HostRuntime/usbmux_tool.py"
        specification = importlib.util.spec_from_file_location("zero_sky_usbmux", module_path)
        assert specification and specification.loader
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        client, relay_left = socket.socketpair()
        relay_right, server = socket.socketpair()
        worker = threading.Thread(target=module.relay, args=(relay_left, relay_right))
        worker.start()
        payload = b"0-sky-relay" * 65536
        received = bytearray()

        def reader() -> None:
            while len(received) < len(payload):
                block = server.recv(65536)
                if not block:
                    return
                received.extend(block)

        consumer = threading.Thread(target=reader)
        consumer.start()
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        consumer.join(timeout=10)
        worker.join(timeout=10)
        client.close()
        server.close()
        self.assertFalse(consumer.is_alive())
        self.assertFalse(worker.is_alive())
        self.assertEqual(bytes(received), payload)


if __name__ == "__main__":
    unittest.main()
