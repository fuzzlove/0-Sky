#!/usr/bin/env python3
"""Generate the loadable Cryptex trust-cache IM4P without device I/O."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct
import uuid


def der_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    value = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(value)]) + value


def der(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_length(len(value)) + value


def code_directories(path: Path):
    data = path.read_bytes()
    start = 0
    while True:
        start = data.find(b"\xfa\xde\x0c\xc0", start)
        if start < 0:
            return
        try:
            _, length, count = struct.unpack_from(">III", data, start)
            if length < 12 + count * 8 or start + length > len(data) or count > 128:
                raise ValueError
            choices = []
            for index in range(count):
                slot, offset = struct.unpack_from(">II", data, start + 12 + index * 8)
                blob = start + offset
                magic, blob_length = struct.unpack_from(">II", data, blob)
                if magic != 0xFADE0C02 or blob_length < 40 or blob + blob_length > start + length:
                    continue
                hash_type = data[blob + 37]
                directory = data[blob:blob + blob_length]
                if hash_type in (2, 3): digest = hashlib.sha256(directory).digest()
                elif hash_type == 1: digest = hashlib.sha1(directory).digest()
                elif hash_type == 4: digest = hashlib.sha384(directory).digest()
                else: continue
                rank = {1: 1, 2: 2, 3: 2, 4: 3}[hash_type]
                choices.append((rank, slot == 0, digest[:20], hash_type))
            if choices:
                _, _, digest, hash_type = max(choices)
                yield digest, hash_type
        except (ValueError, struct.error, IndexError):
            pass
        start += 4


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--empty",
        action="store_true",
        help=(
            "emit an empty cache for a payload whose complete Mach-O set has "
            "already been verified as Apple-signed"
        ),
    )
    args = parser.parse_args()
    entries = set()
    if not args.empty:
        for path in sorted(args.root.rglob("*")):
            if path.is_file() and not path.is_symlink():
                try: entries.update(code_directories(path))
                except OSError: pass
    if not entries and not args.empty:
        raise SystemExit("no signed CodeDirectories found")
    raw = struct.pack("<I", 1) + uuid.uuid4().bytes + struct.pack("<I", len(entries))
    for digest, hash_type in sorted(entries):
        # XNU defines only CS_TRUST_CACHE_AMFID (0x01) for this field.  A
        # normal executable trust entry uses zero; the former 0xC0 value set
        # reserved bits and could acquire unintended policy on newer kernels.
        raw += digest + bytes([hash_type, 0])
    body = der(0x16, b"IM4P") + der(0x16, b"ltrs") + der(0x16, b"cptx") + der(0x04, raw)
    args.output.write_bytes(der(0x30, body))
    print(f"generated {len(entries)} trust-cache entries at {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
