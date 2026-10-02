import struct
import unittest

from zero_sky_compat import macho


def thin_macho(*commands: bytes) -> bytes:
    payload = b"".join(commands)
    return struct.pack(
        "<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 6,
        len(commands), len(payload), 0, 0,
    ) + payload


class MachOUUIDTests(unittest.TestCase):
    def test_uuid_load_command_is_reported(self):
        identifier = bytes.fromhex("00112233445566778899aabbccddeeff")
        record = macho.thin(thin_macho(struct.pack("<II", 0x1B, 24) + identifier))
        self.assertEqual(record["uuid"], identifier.hex())

    def test_uuid_is_absent_when_load_command_is_missing(self):
        self.assertIsNone(macho.thin(thin_macho())["uuid"])


if __name__ == "__main__":
    unittest.main()
