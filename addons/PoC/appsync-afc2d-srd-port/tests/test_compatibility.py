from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "scripts"))
from compatibility import (MachO64, binary_identity, discover_lockdownd_offsets,
                           discover_lockdownd_offset_records,
                           resolve_runtime_address)  # noqa: E402


EXPECTED_OFFSETS = {
    "cf_runloop_return": "0xf454",
    "service_ark_add_entry": "0x1b268",
    "service_ark_in_main_frame": "0x68",
}


class CompatibilityTests(unittest.TestCase):
    def test_analyzes_each_available_exact_build(self) -> None:
        profiles = sorted((PROJECT / "profiles").glob("*.json"))
        self.assertGreaterEqual(len(profiles), 2)
        checked = 0
        for profile_path in profiles:
            profile = json.loads(profile_path.read_text())
            device = profile["device"]
            name = f'{device["product"]}-{device["build"]}'
            lockdownd = PROJECT / "inputs" / ("lockdownd-" + name)
            afcd = PROJECT / "inputs" / ("afcd-" + name)
            if not lockdownd.is_file() or not afcd.is_file():
                continue
            checked += 1
            self.assertEqual(binary_identity(lockdownd),
                             profile["system_binaries"]["/usr/libexec/lockdownd"])
            self.assertEqual(binary_identity(afcd),
                             profile["system_binaries"]["/usr/libexec/afcd"])
            self.assertEqual(
                discover_lockdownd_offsets(MachO64.read(lockdownd)),
                {name: record["value"] for name, record in profile["offsets"].items()},
            )
            records = discover_lockdownd_offset_records(MachO64.read(lockdownd))
            self.assertEqual(records, profile["offsets"])
            self.assertTrue(all(record["validation"]["result"] == "PASS"
                                for record in records.values()))
        if checked == 0:
            self.skipTest("device-derived exact-build inputs are not present")

    def test_generator_reproduces_the_se_profile(self) -> None:
        lockdownd = PROJECT / "inputs/lockdownd-iPhone12,8-24A437"
        afcd = PROJECT / "inputs/afcd-iPhone12,8-24A437"
        if not lockdownd.is_file() or not afcd.is_file():
            self.skipTest("device-derived SE inputs are not present")
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "profile.json"
            subprocess.run([
                sys.executable, str(PROJECT / "scripts/generate-profile.py"),
                "--product", "iPhone12,8", "--version", "27.0",
                "--build", "24A437", "--lockdownd", str(lockdownd),
                "--afcd", str(afcd), "--output", str(output),
                "--shared-cache-uuid", "9744B29F-A357-3E7C-892E-BCDA7A909EED",
                "--shared-cache-size", "6377472000",
            ], check=True, capture_output=True)
            generated = json.loads(output.read_text())
        expected = json.loads((PROJECT / "profiles/iPhone12,8-24A437.json").read_text())
        expected["status"] = "discovered"
        expected.pop("packages", None)
        self.assertEqual(generated, expected)

    def test_discovered_profile_cannot_be_compiled_until_reviewed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "discovered.json"
            value = json.loads(
                (PROJECT / "profiles/iPhone12,8-24A437.json").read_text()
            )
            value["status"] = "discovered"
            profile.write_text(json.dumps(value))
            result = subprocess.run([
                sys.executable,
                str(PROJECT / "scripts/render-compatibility-header.py"),
                str(profile),
                str(Path(temporary) / "compatibility.h"),
            ], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only a reviewed", result.stderr)

    def test_failed_offset_validation_cannot_be_compiled(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "invalid.json"
            value = json.loads(
                (PROJECT / "profiles/iPhone12,8-24A437.json").read_text()
            )
            value["offsets"]["service_ark_add_entry"]["validation"]["result"] = "FAIL"
            profile.write_text(json.dumps(value))
            result = subprocess.run([
                sys.executable,
                str(PROJECT / "scripts/render-compatibility-header.py"),
                str(profile),
                str(Path(temporary) / "compatibility.h"),
            ], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not pass discovery validation", result.stderr)

    def test_header_contains_runtime_semantic_evidence(self) -> None:
        profile = PROJECT / "profiles/iPhone12,8-24A437.json"
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "compatibility.h"
            subprocess.run([
                sys.executable,
                str(PROJECT / "scripts/render-compatibility-header.py"),
                str(profile), str(output),
            ], check=True, capture_output=True)
            header = output.read_text()
        self.assertIn("kExpectedSharedCacheUUID", header)
        self.assertIn("kExpectedRunLoopCallInstruction", header)
        self.assertIn("kExpectedMainSequenceInstructions", header)

    def test_runtime_addresses_are_recomputed_for_each_mapping(self) -> None:
        profile = json.loads(
            (PROJECT / "profiles/iPhone12,8-24A437.json").read_text()
        )
        record = profile["offsets"]["service_ark_add_entry"]
        first = resolve_runtime_address(0x100000000, record)
        second = resolve_runtime_address(0x180000000, record)
        self.assertNotEqual(first, second)
        self.assertEqual(second - first, 0x80000000)
        self.assertNotIn("runtime_address", record)

    def test_changed_binary_invalidates_artifact_hash(self) -> None:
        source = PROJECT / "inputs/lockdownd-iPhone12,8-24A437"
        if not source.is_file():
            self.skipTest("device-derived SE input is not present")
        original = binary_identity(source)
        changed = bytearray(source.read_bytes())
        changed[-1] ^= 1
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "lockdownd"
            path.write_bytes(changed)
            observed = binary_identity(path)
        self.assertEqual(observed["uuid"], original["uuid"])
        self.assertNotEqual(observed["sha256"], original["sha256"])

    def test_missing_import_symbol_disables_discovery(self) -> None:
        source = PROJECT / "inputs/lockdownd-iPhone12,8-24A437"
        if not source.is_file():
            self.skipTest("device-derived SE input is not present")
        changed = source.read_bytes().replace(b"_CFRunLoopRun\0", b"_XFRunLoopRun\0")
        self.assertEqual(len(changed), source.stat().st_size)
        with self.assertRaisesRegex(ValueError, "_CFRunLoopRun"):
            discover_lockdownd_offsets(MachO64(changed))

    def test_ambiguous_runloop_match_disables_discovery(self) -> None:
        source = PROJECT / "inputs/lockdownd-iPhone12,8-24A437"
        if not source.is_file():
            self.skipTest("device-derived SE input is not present")
        image = MachO64.read(source)
        text = image.section("__TEXT", "__text")
        entry = image.vm_for_file_offset(image.entryoff)
        duplicate_pc = entry + 0x10
        target = image.imported_stubs()["_CFRunLoopRun"]
        displacement = target - duplicate_pc
        self.assertEqual(displacement % 4, 0)
        instruction = 0x94000000 | ((displacement >> 2) & 0x03FFFFFF)
        file_offset = text["offset"] + duplicate_pc - text["addr"]
        changed = bytearray(source.read_bytes())
        changed[file_offset:file_offset + 4] = instruction.to_bytes(4, "little")
        with self.assertRaisesRegex(ValueError, "expected one main CFRunLoopRun"):
            discover_lockdownd_offsets(MachO64(bytes(changed)))


if __name__ == "__main__":
    unittest.main()
