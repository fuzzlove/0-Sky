"""Bounded Mach-O load-command transformations for reviewed app adapters."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import struct


MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_ENCRYPTION_INFO_64 = 0x2C
CPU_TYPE_ARM64 = 0x0100000C


@dataclass(frozen=True)
class Slice:
    offset: int
    size: int
    cpu_type: int
    cpu_subtype: int


def _slices(payload: bytes) -> list[Slice]:
    if len(payload) < 4:
        raise ValueError("truncated Mach-O")
    magic = payload[:4]
    if magic == struct.pack("<I", MH_MAGIC_64):
        if len(payload) < 32:
            raise ValueError("truncated Mach-O header")
        cpu_type, cpu_subtype = struct.unpack_from("<ii", payload, 4)
        return [Slice(0, len(payload), cpu_type, cpu_subtype)]
    if magic not in (struct.pack(">I", FAT_MAGIC), struct.pack(">I", FAT_MAGIC_64)):
        raise ValueError("unsupported Mach-O container")
    is_64 = magic == struct.pack(">I", FAT_MAGIC_64)
    if len(payload) < 8:
        raise ValueError("truncated fat header")
    count = struct.unpack_from(">I", payload, 4)[0]
    if not 1 <= count <= 32:
        raise ValueError("invalid fat slice count")
    entry_size = 32 if is_64 else 20
    if 8 + count * entry_size > len(payload):
        raise ValueError("truncated fat architecture table")
    result = []
    for index in range(count):
        position = 8 + index * entry_size
        cpu_type, cpu_subtype = struct.unpack_from(">ii", payload, position)
        if is_64:
            offset, size = struct.unpack_from(">QQ", payload, position + 8)
        else:
            offset, size = struct.unpack_from(">II", payload, position + 8)
        if offset < 8 + count * entry_size or size < 32 or offset + size > len(payload):
            raise ValueError("fat slice is outside the file")
        result.append(Slice(offset, size, cpu_type, cpu_subtype))
    ordered = sorted(result, key=lambda item: item.offset)
    if any(left.offset + left.size > right.offset for left, right in zip(ordered, ordered[1:])):
        raise ValueError("fat Mach-O slices overlap")
    return result


def _commands(payload: bytes | bytearray, item: Slice) -> tuple[int, int, list[tuple[int, int, int]]]:
    if item.cpu_type != CPU_TYPE_ARM64:
        raise ValueError("Mach-O contains a non-arm64 slice")
    if bytes(payload[item.offset:item.offset + 4]) != struct.pack("<I", MH_MAGIC_64):
        raise ValueError("fat member is not a little-endian 64-bit Mach-O")
    ncmds, sizeofcmds = struct.unpack_from("<II", payload, item.offset + 16)
    if ncmds > 4096 or sizeofcmds > item.size - 32:
        raise ValueError("invalid Mach-O load-command bounds")
    cursor = item.offset + 32
    end = cursor + sizeofcmds
    records = []
    for _ in range(ncmds):
        if cursor + 8 > end:
            raise ValueError("truncated Mach-O load command")
        command, command_size = struct.unpack_from("<II", payload, cursor)
        if command_size < 8 or command_size % 4 or cursor + command_size > end:
            raise ValueError("invalid Mach-O load command size")
        records.append((cursor, command, command_size))
        cursor += command_size
    if cursor != end:
        raise ValueError("Mach-O load commands do not match sizeofcmds")
    return ncmds, sizeofcmds, records


def _dylib_name(payload: bytes | bytearray, position: int, size: int) -> str:
    if size < 24:
        raise ValueError("truncated dylib load command")
    name_offset = struct.unpack_from("<I", payload, position + 8)[0]
    if name_offset < 24 or name_offset >= size:
        raise ValueError("invalid dylib load-command name offset")
    raw = bytes(payload[position + name_offset:position + size]).split(b"\0", 1)[0]
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("invalid dylib load-command name") from error


def _first_section_offset(payload: bytes | bytearray, records: list[tuple[int, int, int]]) -> int:
    offsets = []
    for position, command, command_size in records:
        if command != LC_SEGMENT_64:
            continue
        if command_size < 72:
            raise ValueError("truncated 64-bit segment command")
        sections = struct.unpack_from("<I", payload, position + 64)[0]
        if command_size != 72 + sections * 80:
            raise ValueError("invalid 64-bit segment section table")
        for index in range(sections):
            section = position + 72 + index * 80
            offset = struct.unpack_from("<I", payload, section + 48)[0]
            if offset:
                offsets.append(offset)
    if not offsets:
        raise ValueError("Mach-O has no file-backed section")
    return min(offsets)


def add_load_dylib(path: Path, install_name: str) -> dict:
    """Add one LC_LOAD_DYLIB without resizing or blindly editing the binary."""
    path = Path(path)
    if (path.is_symlink() or not path.is_file() or not install_name.startswith("@") or
            "\0" in install_name or len(install_name.encode()) > 1024):
        raise ValueError("invalid Mach-O transformation input")
    payload = bytearray(path.read_bytes())
    slices = _slices(payload)
    encoded = install_name.encode() + b"\0"
    command_size = (24 + len(encoded) + 7) & ~7
    changed = []
    for item in slices:
        ncmds, sizeofcmds, records = _commands(payload, item)
        existing = [_dylib_name(payload, pos, size) for pos, command, size in records
                    if command in (LC_LOAD_DYLIB, 0x18, 0x1F, 0x80000018, 0x8000001F)]
        if install_name in existing:
            continue
        for position, command, command_length in records:
            if command == LC_ENCRYPTION_INFO_64 and command_length >= 24:
                cryptid = struct.unpack_from("<I", payload, position + 16)[0]
                if cryptid:
                    raise ValueError("encrypted Mach-O requires an authorized decrypted source")
        command_end = item.offset + 32 + sizeofcmds
        section_offset = item.offset + _first_section_offset(payload, records)
        if command_end + command_size > section_offset:
            raise ValueError("Mach-O has insufficient load-command padding")
        if any(payload[command_end:command_end + command_size]):
            raise ValueError("Mach-O load-command padding is not empty")
        command = struct.pack("<IIIIII", LC_LOAD_DYLIB, command_size, 24, 0, 0, 0)
        payload[command_end:command_end + len(command)] = command
        payload[command_end + 24:command_end + 24 + len(encoded)] = encoded
        struct.pack_into("<II", payload, item.offset + 16,
                         ncmds + 1, sizeofcmds + command_size)
        changed.append({"cpu_type": item.cpu_type,
                        "cpu_subtype": item.cpu_subtype & 0x00FFFFFF})
    if changed:
        temporary = path.with_name(path.name + ".0sky-macho.tmp")
        temporary.write_bytes(payload)
        temporary.chmod(path.stat().st_mode & 0o777)
        temporary.replace(path)
    return {"install_name": install_name, "changed_slices": changed,
            "slice_count": len(slices), "idempotent": not changed}
