"""Pinned host-runtime assembly reports exact offline recovery actions."""
from __future__ import annotations

from pathlib import Path
import importlib
import importlib.util
import io
import os
import socket
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

from tools import build_host_runtime


class BuildHostRuntimeTests(unittest.TestCase):
    def test_bundled_python_wrapper_never_writes_signed_bundle_bytecode(self) -> None:
        source = Path(build_host_runtime.__file__).read_text(encoding="utf-8")
        self.assertIn("export PYTHONDONTWRITEBYTECODE=1", source)

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

    @unittest.skipUnless(importlib.util.find_spec("zstandard"),
                         "zstandard is supplied by the locked build environment")
    def test_dpkg_extractor_handles_zstandard_without_external_program(self) -> None:
        module_path = Path(__file__).resolve().parents[2] / "bridge/HostRuntime/dpkg_deb.py"
        specification = importlib.util.spec_from_file_location("zero_sky_dpkg_zstd", module_path)
        assert specification and specification.loader
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        zstandard = importlib.import_module("zstandard")
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w") as bundle:
            payload = b"offline-zstandard-proof\n"
            member = tarfile.TarInfo("./var/jb/usr/share/0sky-zstd-proof")
            member.size = len(payload)
            bundle.addfile(member, io.BytesIO(payload))
        compressed = zstandard.ZstdCompressor().compress(archive.getvalue())
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "extract"
            module.extract_archive(compressed, destination)
            self.assertEqual(
                (destination / "var/jb/usr/share/0sky-zstd-proof").read_bytes(), payload
            )

    def test_dpkg_zstandard_missing_dependency_has_exact_repair_action(self) -> None:
        module_path = Path(__file__).resolve().parents[2] / "bridge/HostRuntime/dpkg_deb.py"
        specification = importlib.util.spec_from_file_location("zero_sky_dpkg_no_zstd", module_path)
        assert specification and specification.loader
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with patch.object(module.importlib, "import_module", side_effect=ImportError):
            with self.assertRaisesRegex(RuntimeError, "Repair Host Dependencies"):
                module._write_uncompressed_tar(b"\x28\xb5\x2f\xfd", io.BytesIO())

    def test_dpkg_decompression_enforces_expanded_size_limit(self) -> None:
        module_path = Path(__file__).resolve().parents[2] / "bridge/HostRuntime/dpkg_deb.py"
        specification = importlib.util.spec_from_file_location("zero_sky_dpkg_bound", module_path)
        assert specification and specification.loader
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with patch.object(module, "MAX_EXPANDED_ARCHIVE_SIZE", 3):
            with self.assertRaisesRegex(RuntimeError, "4 GiB safety limit"):
                module._copy_bounded(io.BytesIO(b"four"), io.BytesIO())

    def test_dpkg_builder_is_reproducible_root_owned_and_extractable(self) -> None:
        module_path = Path(__file__).resolve().parents[2] / "bridge/HostRuntime/dpkg_deb.py"
        specification = importlib.util.spec_from_file_location("zero_sky_dpkg_build", module_path)
        assert specification and specification.loader
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            package_root = root / "root"
            control = package_root / "DEBIAN/control"
            payload = package_root / "var/jb/usr/bin/fixture"
            control.parent.mkdir(parents=True)
            payload.parent.mkdir(parents=True)
            control.write_text(
                "Package: codes.example.fixture\nVersion: 1.0\n"
                "Architecture: iphoneos-arm64\nDescription: fixture\n"
            )
            payload.write_text("#!/bin/sh\nexit 0\n")
            payload.chmod(0o755)
            first, second = root / "first.deb", root / "second.deb"
            with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1234567890"}):
                module.build_package(package_root, first)
                module.build_package(package_root, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(
                module.control_fields(module.members(first)["control.tar.gz"])["Package"],
                "codes.example.fixture",
            )
            destination = root / "extract"
            module.extract_archive(module.members(first)["data.tar.gz"], destination)
            extracted = destination / "var/jb/usr/bin/fixture"
            self.assertEqual(extracted.read_text(), payload.read_text())
            self.assertEqual(extracted.stat().st_mode & 0o777, 0o755)
            with tarfile.open(fileobj=io.BytesIO(module.members(first)["data.tar.gz"]), mode="r:*") as archive:
                member = archive.getmember("./var/jb/usr/bin/fixture")
                self.assertEqual((member.uid, member.gid), (0, 0))

    def test_dpkg_builder_rejects_escaping_symlink_chain(self) -> None:
        module_path = Path(__file__).resolve().parents[2] / "bridge/HostRuntime/dpkg_deb.py"
        specification = importlib.util.spec_from_file_location("zero_sky_dpkg_links", module_path)
        assert specification and specification.loader
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            package_root = root / "root"
            control = package_root / "DEBIAN/control"
            payload = package_root / "var/jb/usr/share"
            control.parent.mkdir(parents=True)
            payload.mkdir(parents=True)
            control.write_text(
                "Package: codes.example.fixture\nVersion: 1.0\n"
                "Architecture: iphoneos-arm64\nDescription: fixture\n"
            )
            (payload / "outside").symlink_to(Path(folder).parent)
            (payload / "chain").symlink_to("outside")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                module.build_package(package_root, root / "unsafe.deb")

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
