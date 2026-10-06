#!/usr/bin/env python3
"""Render reviewed exact-build constants for the AFC2 tweak."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import uuid


def offset(record: object, name: str) -> int:
    if not isinstance(record, dict) or not isinstance(record.get("value"), str):
        raise ValueError(f"profile offset {name} is not a hexadecimal string")
    result = int(record["value"], 0)
    if result <= 0:
        raise ValueError(f"profile offset {name} is invalid")
    return result


def validated_record(profile: dict, name: str, expected_type: str) -> dict:
    record = profile.get("offsets", {}).get(name)
    if not isinstance(record, dict):
        raise ValueError(f"profile offset {name} is missing")
    if record.get("type") != expected_type:
        raise ValueError(f"profile offset {name} has the wrong type")
    if record.get("validation", {}).get("result") != "PASS":
        raise ValueError(f"profile offset {name} did not pass discovery validation")
    if expected_type == "image_relative_virtual_address":
        if (record.get("image") != "/usr/libexec/lockdownd"
                or record.get("expected_section") != "__TEXT,__text"):
            raise ValueError(f"profile offset {name} has the wrong image or section")
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    profile = json.loads(args.profile.read_text())
    if profile.get("schema") != 2 or profile.get("status") != "reviewed":
        raise ValueError("only a reviewed schema-2 profile may be compiled")
    if profile.get("architecture") != "arm64e":
        raise ValueError("profile architecture must be arm64e")
    binaries = profile.get("system_binaries", {})
    lockdown = binaries.get("/usr/libexec/lockdownd", {})
    afcd = binaries.get("/usr/libexec/afcd", {})
    if (lockdown.get("architecture") != "arm64e"
            or afcd.get("architecture") != "arm64e"):
        raise ValueError("profile system binaries must be arm64e")
    identifier = uuid.UUID(lockdown["uuid"])
    runloop_record = validated_record(
        profile, "cf_runloop_return", "image_relative_virtual_address"
    )
    add_entry_record = validated_record(
        profile, "service_ark_add_entry", "image_relative_virtual_address"
    )
    frame_record = validated_record(
        profile, "service_ark_in_main_frame", "frame_relative_displacement"
    )
    values = {
        "kCFRunLoopReturnOffset": offset(runloop_record, "cf_runloop_return"),
        "kServiceArkAddEntryOffset": offset(add_entry_record, "service_ark_add_entry"),
        "kServiceArkInMainFrameOffset": offset(frame_record, "service_ark_in_main_frame"),
    }
    lines = [
        "// Generated from " + args.profile.name + "; do not edit.",
        "#pragma once",
        "",
    ]
    lines.extend(
        f"static const uintptr_t {name} = 0x{value:x};" for name, value in values.items()
    )
    runloop_word = int(runloop_record["evidence"]["call_instruction"], 0)
    add_word0 = int(add_entry_record["evidence"]["entry_instruction_0"], 0)
    add_word1 = int(add_entry_record["evidence"]["entry_instruction_1"], 0)
    frame_evidence = frame_record["evidence"]
    main_sequence_offset = int(frame_evidence["sequence_image_offset"], 0)
    main_sequence_words = [int(word, 0) for word in frame_evidence["instruction_words"]]
    if len(main_sequence_words) != 4:
        raise ValueError("main-frame evidence must contain four instruction words")
    lines.extend([
        f"static const uint32_t kExpectedRunLoopCallInstruction = 0x{runloop_word:08x};",
        f"static const uint32_t kExpectedAddEntryInstruction0 = 0x{add_word0:08x};",
        f"static const uint32_t kExpectedAddEntryInstruction1 = 0x{add_word1:08x};",
        f"static const uintptr_t kExpectedMainSequenceOffset = 0x{main_sequence_offset:x};",
        "static const uint32_t kExpectedMainSequenceInstructions[4] = {",
        "    " + ", ".join(f"0x{word:08x}" for word in main_sequence_words),
        "};",
    ])
    byte_values = ", ".join(f"0x{value:02x}" for value in identifier.bytes)
    lines.extend([
        "static const uint8_t kExpectedLockdownUUID[16] = {",
        "    " + byte_values,
        "};",
    ])
    caches = profile.get("dyld_shared_caches", [])
    if len(caches) != 1 or caches[0].get("kind") != "process_primary_shared_cache":
        raise ValueError("profile must identify one process primary dyld shared cache")
    if not isinstance(caches[0].get("mapped_size"), int) or caches[0]["mapped_size"] <= 0:
        raise ValueError("profile dyld shared-cache size is invalid")
    cache_values = ", ".join(
        f"0x{value:02x}" for value in uuid.UUID(caches[0]["uuid"]).bytes
    )
    lines.extend([
        "static const uint8_t kExpectedSharedCacheUUID[16] = {",
        "    " + cache_values,
        "};",
        "",
    ])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
