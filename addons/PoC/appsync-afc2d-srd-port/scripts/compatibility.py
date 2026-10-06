#!/usr/bin/env python3
"""Exact-binary compatibility profiles and arm64e lockdownd analysis."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct
import uuid


LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_UUID = 0x1B
LC_MAIN = 0x80000028
S_SYMBOL_STUBS = 0x8
MH_MAGIC_64 = 0xFEEDFACF
REQUIRED_OFFSETS = {
    "cf_runloop_return": "image_relative_virtual_address",
    "service_ark_add_entry": "image_relative_virtual_address",
    "service_ark_in_main_frame": "frame_relative_displacement",
}


def _sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


class MachO64:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 32:
            raise ValueError("truncated Mach-O header")
        header = struct.unpack_from("<IiiIIIII", data, 0)
        if header[0] != MH_MAGIC_64:
            raise ValueError("expected a little-endian 64-bit Mach-O")
        self.cputype, self.cpusubtype = header[1:3]
        if self.cputype != 0x0100000C or self.cpusubtype & 0x00FFFFFF != 2:
            raise ValueError("expected an arm64e Mach-O")
        self.ncmds, self.sizeofcmds = header[4:6]
        if self.ncmds > 4096 or 32 + self.sizeofcmds > len(data):
            raise ValueError("invalid Mach-O load-command bounds")
        self.commands: list[tuple[int, bytes]] = []
        self.segments: list[dict] = []
        self.sections: list[dict] = []
        self.image_uuid: str | None = None
        self.entryoff: int | None = None
        self.symtab: tuple[int, int, int, int] | None = None
        self.indirectsymoff: int | None = None
        self.nindirectsyms = 0
        cursor = 32
        for _ in range(self.ncmds):
            if cursor + 8 > len(data):
                raise ValueError("truncated Mach-O load command")
            command, size = struct.unpack_from("<II", data, cursor)
            if size < 8 or cursor + size > len(data):
                raise ValueError("invalid Mach-O load command")
            raw = data[cursor:cursor + size]
            self.commands.append((command, raw))
            if command == LC_UUID:
                if size < 24 or self.image_uuid is not None:
                    raise ValueError("invalid LC_UUID")
                self.image_uuid = str(uuid.UUID(bytes=raw[8:24])).upper()
            elif command == LC_MAIN:
                if size < 24:
                    raise ValueError("invalid LC_MAIN")
                self.entryoff = struct.unpack_from("<Q", raw, 8)[0]
            elif command == LC_SYMTAB:
                if size < 24:
                    raise ValueError("invalid LC_SYMTAB")
                self.symtab = struct.unpack_from("<IIII", raw, 8)
            elif command == LC_DYSYMTAB:
                if size < 80:
                    raise ValueError("invalid LC_DYSYMTAB")
                self.indirectsymoff, self.nindirectsyms = struct.unpack_from(
                    "<II", raw, 56
                )
            elif command == LC_SEGMENT_64:
                self._parse_segment(raw)
            cursor += size
        if cursor != 32 + self.sizeofcmds:
            raise ValueError("load commands do not fill sizeofcmds")
        if self.image_uuid is None:
            raise ValueError("Mach-O has no LC_UUID")
        bases = [item["vmaddr"] - item["fileoff"] for item in self.segments
                 if item["filesize"] and item["fileoff"] == 0]
        if not bases:
            raise ValueError("Mach-O has no file-backed image base")
        self.image_base = min(bases)

    @classmethod
    def read(cls, path: Path) -> "MachO64":
        return cls(path.read_bytes())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def _parse_segment(self, raw: bytes) -> None:
        if len(raw) < 72:
            raise ValueError("invalid LC_SEGMENT_64")
        values = struct.unpack_from("<II16sQQQQiiII", raw, 0)
        name = values[2].split(b"\0", 1)[0].decode("ascii", "strict")
        segment = {
            "name": name, "vmaddr": values[3], "vmsize": values[4],
            "fileoff": values[5], "filesize": values[6], "nsects": values[9],
        }
        if 72 + segment["nsects"] * 80 > len(raw):
            raise ValueError("invalid section table")
        if (segment["fileoff"] > len(self.data)
                or segment["filesize"] > len(self.data) - segment["fileoff"]):
            raise ValueError("segment file range is out of bounds")
        self.segments.append(segment)
        for index in range(segment["nsects"]):
            values = struct.unpack_from("<16s16sQQIIIIIIII", raw, 72 + index * 80)
            section = {
                "name": values[0].split(b"\0", 1)[0].decode("ascii", "strict"),
                "segment": values[1].split(b"\0", 1)[0].decode("ascii", "strict"),
                "addr": values[2], "size": values[3], "offset": values[4],
                "flags": values[8], "reserved1": values[9],
                "reserved2": values[10],
            }
            section_type = section["flags"] & 0xFF
            if section_type not in (1, 0xC, 0x12):  # zerofill variants
                if (section["offset"] > len(self.data)
                        or section["size"] > len(self.data) - section["offset"]):
                    raise ValueError("section file range is out of bounds")
            self.sections.append(section)

    def section(self, segment: str, name: str) -> dict:
        matches = [item for item in self.sections
                   if item["segment"] == segment and item["name"] == name]
        if len(matches) != 1:
            raise ValueError(f"expected one {segment},{name} section")
        return matches[0]

    def vm_for_file_offset(self, offset: int) -> int:
        for segment in self.segments:
            start, size = segment["fileoff"], segment["filesize"]
            if start <= offset < start + size:
                return segment["vmaddr"] + offset - start
        raise ValueError(f"file offset {offset:#x} is not mapped")

    def instructions(self, section: dict | None = None):
        section = section or self.section("__TEXT", "__text")
        raw = self.data[section["offset"]:section["offset"] + section["size"]]
        for offset in range(0, len(raw) - 3, 4):
            yield section["addr"] + offset, struct.unpack_from("<I", raw, offset)[0]

    def imported_stubs(self) -> dict[str, int]:
        if self.symtab is None or self.indirectsymoff is None:
            raise ValueError("Mach-O has no indirect symbol metadata")
        symoff, nsyms, stroff, strsize = self.symtab
        if (symoff + nsyms * 16 > len(self.data)
                or stroff + strsize > len(self.data)
                or self.indirectsymoff + self.nindirectsyms * 4 > len(self.data)):
            raise ValueError("invalid symbol table bounds")
        names = []
        strings = self.data[stroff:stroff + strsize]
        for index in range(nsyms):
            string_index = struct.unpack_from("<I", self.data, symoff + index * 16)[0]
            if string_index >= len(strings):
                names.append("")
                continue
            end = strings.find(b"\0", string_index)
            if end < 0:
                raise ValueError("unterminated symbol name")
            names.append(strings[string_index:end].decode("utf-8", "replace"))
        indirect = struct.unpack_from(
            f"<{self.nindirectsyms}I", self.data, self.indirectsymoff
        )
        result = {}
        for section in self.sections:
            if section["flags"] & 0xFF != S_SYMBOL_STUBS or not section["reserved2"]:
                continue
            count = section["size"] // section["reserved2"]
            for index in range(count):
                indirect_index = section["reserved1"] + index
                if indirect_index >= len(indirect):
                    raise ValueError("stub indirect-symbol index is out of bounds")
                symbol_index = indirect[indirect_index]
                if symbol_index & 0xC0000000 or symbol_index >= len(names):
                    continue
                result[names[symbol_index]] = (
                    section["addr"] + index * section["reserved2"]
                )
        return result


def _decode_adrp(pc: int, instruction: int) -> tuple[int, int] | None:
    if instruction & 0x9F000000 != 0x90000000:
        return None
    immediate = ((instruction >> 29) & 0x3) | (((instruction >> 5) & 0x7FFFF) << 2)
    target = (pc & ~0xFFF) + (_sign_extend(immediate, 21) << 12)
    return instruction & 0x1F, target


def _decode_add_immediate(instruction: int) -> tuple[int, int, int] | None:
    if instruction & 0xFF000000 != 0x91000000:
        return None
    shift = 12 if instruction & (1 << 22) else 0
    immediate = ((instruction >> 10) & 0xFFF) << shift
    return instruction & 0x1F, (instruction >> 5) & 0x1F, immediate


def _decode_bl(pc: int, instruction: int) -> int | None:
    if instruction & 0xFC000000 != 0x94000000:
        return None
    return pc + (_sign_extend(instruction & 0x3FFFFFF, 26) << 2)


def _is_prologue(instruction: int) -> bool:
    return instruction in (0xD503237F, 0xD503233F)  # pacibsp / paciasp


def _previous_prologue(instructions: list[tuple[int, int]], address: int,
                       distance: int = 0x600) -> int:
    matches = [pc for pc, instruction in instructions
               if address - distance <= pc <= address and _is_prologue(instruction)]
    if not matches:
        raise ValueError(f"no arm64e function prologue before {address:#x}")
    return max(matches)


def _adrp_add_xrefs(instructions: list[tuple[int, int]], target: int):
    result = []
    for (pc, first), (next_pc, second) in zip(instructions, instructions[1:]):
        if next_pc != pc + 4:
            continue
        adrp = _decode_adrp(pc, first)
        add = _decode_add_immediate(second)
        if adrp is None or add is None:
            continue
        adrp_register, page = adrp
        destination, source, immediate = add
        if destination == source == adrp_register and page + immediate == target:
            result.append((pc, next_pc, destination))
    return result


def discover_lockdownd_offsets(macho: MachO64) -> dict[str, str]:
    """Derive the three build-sensitive values using structural references."""
    text = list(macho.instructions())
    stubs = macho.imported_stubs()
    runloop_stub = stubs.get("_CFRunLoopRun")
    if runloop_stub is None or macho.entryoff is None:
        raise ValueError("lockdownd is missing LC_MAIN or _CFRunLoopRun")
    entry = macho.vm_for_file_offset(macho.entryoff)
    runloop_calls = [pc for pc, instruction in text
                     if entry <= pc < entry + 0x4000
                     and _decode_bl(pc, instruction) == runloop_stub]
    if len(runloop_calls) != 1:
        raise ValueError(f"expected one main CFRunLoopRun call, found {len(runloop_calls)}")
    runloop_return = runloop_calls[0] + 4

    marker = b"service_ark_add_entry_block_invoke\0"
    marker_offsets = []
    cursor = 0
    while True:
        cursor = macho.data.find(marker, cursor)
        if cursor < 0:
            break
        marker_offsets.append(cursor)
        cursor += 1
    if len(marker_offsets) != 1:
        raise ValueError(f"expected one service ark marker, found {len(marker_offsets)}")
    marker_address = macho.vm_for_file_offset(marker_offsets[0])
    marker_xrefs = _adrp_add_xrefs(text, marker_address)
    block_starts = {_previous_prologue(text, item[0]) for item in marker_xrefs}
    if len(block_starts) != 1:
        raise ValueError("service ark block function was not uniquely identified")
    block_start = block_starts.pop()
    block_xrefs = _adrp_add_xrefs(text, block_start)
    add_entry_starts = {_previous_prologue(text, item[0]) for item in block_xrefs
                        if item[0] < block_start}
    if len(add_entry_starts) != 1:
        raise ValueError("service_ark_add_entry was not uniquely identified")
    add_entry = add_entry_starts.pop()

    # In main, service_ark_load materializes its result as a two-word local.
    # Find the compiler sequence that passes two stack locals, calls the loader,
    # and stores its return value into the first word. The ark pointer occupies
    # the second word; express its location relative to main's frame pointer.
    entry_rows = [(pc, insn) for pc, insn in text if entry <= pc < runloop_calls[0]]
    frame_offsets = []
    frame_pointer_from_sp = None
    for _, instruction in entry_rows[:20]:
        add = _decode_add_immediate(instruction)
        if add and add[0] == 29 and add[1] == 31:
            frame_pointer_from_sp = add[2]
            break
    if frame_pointer_from_sp is None:
        raise ValueError("main frame-pointer setup was not identified")
    for index in range(len(entry_rows) - 4):
        sequence = entry_rows[index:index + 4]
        add0 = _decode_add_immediate(sequence[0][1])
        add1 = _decode_add_immediate(sequence[1][1])
        call = _decode_bl(sequence[2][0], sequence[2][1])
        store = sequence[3][1]
        if not (add0 and add1 and call is not None):
            continue
        if not (add0[0] == 0 and add0[1] == 31
                and add1[0] == 1 and add1[1] == 31):
            continue
        if store & 0xFFC00000 != 0xF9000000:
            continue
        store_register = store & 0x1F
        store_base = (store >> 5) & 0x1F
        store_offset = ((store >> 10) & 0xFFF) * 8
        if store_register == 0 and store_base == 31 and store_offset == add0[2]:
            candidate = frame_pointer_from_sp - (add0[2] + 8)
            if candidate > 0 and candidate % 8 == 0:
                frame_offsets.append(candidate)
    if len(frame_offsets) != 1:
        raise ValueError("service ark main-frame slot was not uniquely identified")

    return {
        "cf_runloop_return": hex(runloop_return - macho.image_base),
        "service_ark_add_entry": hex(add_entry - macho.image_base),
        "service_ark_in_main_frame": hex(frame_offsets[0]),
    }


def discover_lockdownd_offset_records(macho: MachO64) -> dict[str, dict]:
    """Return typed offsets with reproducible discovery and validation evidence."""
    simple = discover_lockdownd_offsets(macho)
    text = list(macho.instructions())
    instruction_by_address = dict(text)
    image_base = macho.image_base
    runloop_return = image_base + int(simple["cf_runloop_return"], 0)
    add_entry = image_base + int(simple["service_ark_add_entry"], 0)
    marker = b"service_ark_add_entry_block_invoke\0"
    marker_file_offset = macho.data.index(marker)
    marker_address = macho.vm_for_file_offset(marker_file_offset)
    marker_xrefs = _adrp_add_xrefs(text, marker_address)
    block_start = _previous_prologue(text, marker_xrefs[0][0])
    block_xrefs = [item for item in _adrp_add_xrefs(text, block_start)
                   if item[0] < block_start]

    entry = macho.vm_for_file_offset(macho.entryoff) if macho.entryoff is not None else 0
    frame_pattern = []
    frame_pointer_from_sp = None
    entry_rows = [(pc, insn) for pc, insn in text if entry <= pc < runloop_return]
    for _, instruction in entry_rows[:20]:
        add = _decode_add_immediate(instruction)
        if add and add[0] == 29 and add[1] == 31:
            frame_pointer_from_sp = add[2]
            break
    for index in range(len(entry_rows) - 4):
        rows = entry_rows[index:index + 4]
        add0 = _decode_add_immediate(rows[0][1])
        add1 = _decode_add_immediate(rows[1][1])
        call = _decode_bl(rows[2][0], rows[2][1])
        store = rows[3][1]
        if (add0 and add1 and call is not None
                and add0[0] == 0 and add0[1] == 31
                and add1[0] == 1 and add1[1] == 31
                and store & 0xFFC00000 == 0xF9000000
                and store & 0x1F == 0 and (store >> 5) & 0x1F == 31
                and ((store >> 10) & 0xFFF) * 8 == add0[2]
                and frame_pointer_from_sp - (add0[2] + 8)
                    == int(simple["service_ark_in_main_frame"], 0)):
            frame_pattern.append((rows, add0[2], frame_pointer_from_sp))
    if len(frame_pattern) != 1:
        raise ValueError("frame-slot evidence was not unique")
    frame_rows, local_offset, frame_pointer_from_sp = frame_pattern[0]

    def image_record(value: str, meaning: str, method: str, evidence: dict) -> dict:
        relative = int(value, 0)
        address = image_base + relative
        file_offset = None
        for segment in macho.segments:
            start = segment["vmaddr"]
            if start <= address < start + segment["filesize"]:
                file_offset = segment["fileoff"] + address - start
                break
        if file_offset is None:
            raise ValueError(f"discovered address {address:#x} is not file-backed")
        return {
            "value": value,
            "type": "image_relative_virtual_address",
            "image": "/usr/libexec/lockdownd",
            "unslid_virtual_address": hex(address),
            "file_offset": hex(file_offset),
            "expected_section": "__TEXT,__text",
            "runtime_resolution": "current_lockdownd_mach_header + value",
            "meaning": meaning,
            "discovery_method": method,
            "evidence": evidence,
            "validation": {
                "result": "PASS",
                "checks": [
                    "unique candidate",
                    "inside __TEXT,__text",
                    "instruction semantics matched",
                    "file and virtual bounds checked",
                ],
            },
        }

    runloop_instruction = instruction_by_address[runloop_return - 4]
    add_instruction0 = instruction_by_address[add_entry]
    add_instruction1 = instruction_by_address[add_entry + 4]
    records = {
        "cf_runloop_return": image_record(
            simple["cf_runloop_return"],
            "saved return PC immediately after lockdownd main calls _CFRunLoopRun",
            "resolve _CFRunLoopRun through the indirect symbol table and require "
            "one BL from LC_MAIN",
            {
                "candidate_count": 1,
                "call_site_image_offset": hex(runloop_return - 4 - image_base),
                "call_instruction": hex(runloop_instruction),
                "instruction_mask": "0xfc000000",
                "resolved_symbol": "_CFRunLoopRun",
            },
        ),
        "service_ark_add_entry": image_record(
            simple["service_ark_add_entry"],
            "entry point of lockdownd's internal service_ark_add_entry function",
            "xref the unique service_ark_add_entry_block_invoke marker, identify "
            "its arm64e function, then require one enclosing function reference",
            {
                "candidate_count": 1,
                "marker_file_offset": hex(marker_file_offset),
                "marker_unslid_virtual_address": hex(marker_address),
                "marker_xref_count": len(marker_xrefs),
                "block_start_image_offset": hex(block_start - image_base),
                "block_reference_count": len(block_xrefs),
                "entry_instruction_0": hex(add_instruction0),
                "entry_instruction_1": hex(add_instruction1),
            },
        ),
        "service_ark_in_main_frame": {
            "value": simple["service_ark_in_main_frame"],
            "type": "frame_relative_displacement",
            "base": "lockdownd LC_MAIN frame pointer",
            "operation": "subtract",
            "unslid_virtual_address": None,
            "file_offset": None,
            "expected_section": None,
            "runtime_resolution": "main_frame_pointer - value",
            "meaning": "stack slot containing the live service-ark pointer",
            "discovery_method": "require the unique main sequence that passes two "
            "stack locals to the service-ark loader and stores its result",
            "evidence": {
                "candidate_count": 1,
                "main_image_offset": hex(entry - image_base),
                "sequence_image_offset": hex(frame_rows[0][0] - image_base),
                "instruction_words": [hex(row[1]) for row in frame_rows],
                "frame_pointer_from_sp": hex(frame_pointer_from_sp),
                "first_local_from_sp": hex(local_offset),
                "ark_slot_from_sp": hex(local_offset + 8),
            },
            "validation": {
                "result": "PASS",
                "checks": [
                    "unique candidate",
                    "positive aligned displacement",
                    "LC_MAIN bounds checked",
                    "four-instruction semantic sequence matched",
                ],
            },
        },
    }
    return records


def binary_identity(path: Path) -> dict:
    image = MachO64.read(path)
    return {"uuid": image.image_uuid, "sha256": image.sha256,
            "size": len(image.data), "architecture": "arm64e"}


def validate_profile(profile: dict) -> None:
    """Validate the reusable, non-runtime compatibility profile schema."""
    if profile.get("schema") != 2:
        raise ValueError("profile schema must be 2")
    if profile.get("status") not in ("discovered", "reviewed"):
        raise ValueError("profile status must be discovered or reviewed")
    if profile.get("architecture") != "arm64e":
        raise ValueError("profile architecture must be arm64e")
    device = profile.get("device")
    if not isinstance(device, dict) or any(
            not isinstance(device.get(key), str) or not device[key]
            for key in ("product", "version", "build")):
        raise ValueError("profile device identity is incomplete")

    binaries = profile.get("system_binaries")
    required_binaries = {"/usr/libexec/lockdownd", "/usr/libexec/afcd"}
    if not isinstance(binaries, dict) or set(binaries) != required_binaries:
        raise ValueError("profile system-binary set is invalid")
    for path, identity in binaries.items():
        if not isinstance(identity, dict) or identity.get("architecture") != "arm64e":
            raise ValueError(f"profile binary architecture is invalid: {path}")
        try:
            uuid.UUID(identity["uuid"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"profile binary UUID is invalid: {path}") from error
        digest = identity.get("sha256")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(character not in "0123456789abcdefABCDEF" for character in digest)):
            raise ValueError(f"profile binary SHA-256 is invalid: {path}")
        if not isinstance(identity.get("size"), int) or identity["size"] <= 0:
            raise ValueError(f"profile binary size is invalid: {path}")

    caches = profile.get("dyld_shared_caches")
    if (not isinstance(caches, list) or len(caches) != 1
            or caches[0].get("kind") != "process_primary_shared_cache"):
        raise ValueError("profile primary dyld shared-cache identity is invalid")
    try:
        uuid.UUID(caches[0]["uuid"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("profile dyld shared-cache UUID is invalid") from error
    if (not isinstance(caches[0].get("mapped_size"), int)
            or caches[0]["mapped_size"] <= 0):
        raise ValueError("profile dyld shared-cache size is invalid")

    offsets = profile.get("offsets")
    if not isinstance(offsets, dict) or set(offsets) != set(REQUIRED_OFFSETS):
        raise ValueError("profile offset record set is invalid")
    for name, expected_type in REQUIRED_OFFSETS.items():
        record = offsets[name]
        if not isinstance(record, dict) or record.get("type") != expected_type:
            raise ValueError(f"profile offset type is invalid: {name}")
        try:
            value = int(record["value"], 0)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"profile offset value is invalid: {name}") from error
        if value <= 0 or "runtime_address" in record:
            raise ValueError(f"profile offset value is invalid: {name}")
        validation = record.get("validation")
        evidence = record.get("evidence")
        if not isinstance(validation, dict) or validation.get("result") != "PASS":
            raise ValueError(f"profile offset validation failed: {name}")
        if not isinstance(evidence, dict) or evidence.get("candidate_count") != 1:
            raise ValueError(f"profile offset is not unique: {name}")
        if expected_type == "image_relative_virtual_address" and (
                record.get("image") != "/usr/libexec/lockdownd"
                or record.get("expected_section") != "__TEXT,__text"
                or not isinstance(record.get("file_offset"), str)
                or not isinstance(record.get("unslid_virtual_address"), str)):
            raise ValueError(f"profile image-relative evidence is invalid: {name}")


def load_profiles(directory: Path) -> list[dict]:
    profiles = []
    for path in sorted(directory.glob("*.json")):
        value = json.loads(path.read_text())
        try:
            validate_profile(value)
        except ValueError as error:
            raise ValueError(f"invalid compatibility profile {path}: {error}") from error
        value["_path"] = str(path)
        profiles.append(value)
    if not profiles:
        raise ValueError(f"no compatibility profiles found in {directory}")
    return profiles


def offset_value(profile: dict, name: str) -> int:
    record = profile.get("offsets", {}).get(name)
    if not isinstance(record, dict) or not isinstance(record.get("value"), str):
        raise ValueError(f"profile has no typed offset record for {name}")
    return int(record["value"], 0)


def resolve_runtime_address(image_load_address: int, record: dict) -> int:
    """Resolve one image-relative record for the current process mapping only."""
    if record.get("type") != "image_relative_virtual_address":
        raise ValueError("record is not an image-relative virtual address")
    value = int(record["value"], 0)
    if image_load_address <= 0 or value <= 0:
        raise ValueError("invalid runtime image base or offset")
    resolved = image_load_address + value
    if resolved > 0xFFFFFFFFFFFFFFFF:
        raise OverflowError("runtime address overflow")
    return resolved
