from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))

from zero_sky_compat.macho_edit import (CPU_TYPE_ARM64, LC_LOAD_DYLIB,
                                        MH_MAGIC_64, add_load_dylib)


def fixture() -> bytes:
    segment_size = 72 + 80
    header = struct.pack("<IiiIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, 0,
                         2, 1, segment_size, 0, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, segment_size, b"__TEXT\0" * 2,
                          0, 0x2000, 0, 0x1100, 5, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text\0" * 2, b"__TEXT\0" * 2,
                          0x1000, 0x100, 0x1000, 2, 0, 0, 0, 0, 0, 0)
    payload = bytearray(0x1100)
    payload[:len(header + segment + section)] = header + segment + section
    payload[0x1000:0x1004] = b"CODE"
    return bytes(payload)


class MachOEditTests(unittest.TestCase):
    def test_add_load_dylib_is_structured_and_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Fixture"
            path.write_bytes(fixture())
            name = "@executable_path/Frameworks/0SkyCraneBootstrap.dylib"
            first = add_load_dylib(path, name)
            self.assertFalse(first["idempotent"])
            self.assertEqual(first["changed_slices"], [
                {"cpu_type": CPU_TYPE_ARM64, "cpu_subtype": 0}])
            data = path.read_bytes()
            ncmds, size = struct.unpack_from("<II", data, 16)
            self.assertEqual(ncmds, 2)
            position = 32 + 152
            command, command_size, name_offset = struct.unpack_from("<III", data, position)
            self.assertEqual(command, LC_LOAD_DYLIB)
            self.assertEqual(name_offset, 24)
            observed = data[position + name_offset:position + command_size].split(b"\0", 1)[0]
            self.assertEqual(observed.decode(), name)
            self.assertEqual(data[0x1000:0x1004], b"CODE")
            second = add_load_dylib(path, name)
            self.assertTrue(second["idempotent"])
            self.assertEqual(path.read_bytes(), data)

    def test_rejects_nonempty_header_padding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Fixture"
            data = bytearray(fixture())
            data[32 + 152] = 1
            path.write_bytes(data)
            with self.assertRaisesRegex(ValueError, "padding is not empty"):
                add_load_dylib(path, "@rpath/Test.dylib")


if __name__ == "__main__":
    unittest.main()
