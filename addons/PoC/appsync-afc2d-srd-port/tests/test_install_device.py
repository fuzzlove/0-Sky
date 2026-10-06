from __future__ import annotations

import importlib.util
import copy
import shlex
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install-device.py"
SPEC = importlib.util.spec_from_file_location("install_device", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
install_device = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(install_device)


class CompatibilityPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = dict(install_device.SUPPORTED_DEVICE)
        self.binaries = {
            path: dict(expected)
            for path, expected in install_device.SYSTEM_BINARIES.items()
        }
        self.caches = [dict(item) for item in
                       install_device._DEFAULT_PROFILE["dyld_shared_caches"]]

    def test_accepts_only_the_exact_reviewed_target(self) -> None:
        install_device.validate_compatibility(
            self.identity, self.binaries, shared_caches=self.caches
        )

    def test_rejects_wrong_build_before_binary_match_can_help(self) -> None:
        self.identity["build"] = "24A9999z"
        with self.assertRaisesRegex(RuntimeError, "build expected.*24A5390f"):
            install_device.validate_compatibility(self.identity)

    def test_public_identity_check_does_not_require_binary_evidence(self) -> None:
        install_device.validate_compatibility(self.identity)

    def test_rejects_wrong_lockdownd_uuid(self) -> None:
        self.binaries["/usr/libexec/lockdownd"]["uuid"] = (
            "00000000-0000-0000-0000-000000000000"
        )
        with self.assertRaisesRegex(RuntimeError, "lockdownd.*uuid expected"):
            install_device.validate_compatibility(
                self.identity, self.binaries, shared_caches=self.caches
            )

    def test_rejects_wrong_afcd_hash(self) -> None:
        self.binaries["/usr/libexec/afcd"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "afcd.*sha256 expected"):
            install_device.validate_compatibility(
                self.identity, self.binaries, shared_caches=self.caches
            )

    def test_rejects_stale_shared_cache_profile(self) -> None:
        caches = [dict(item) for item in self.caches]
        caches[0]["uuid"] = "00000000-0000-0000-0000-000000000000"
        with self.assertRaisesRegex(RuntimeError, "dyld shared-cache identities"):
            install_device.validate_compatibility(
                self.identity, self.binaries, shared_caches=caches
            )

    def test_rejects_missing_shared_cache_evidence(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "identity evidence is missing"):
            install_device.validate_compatibility(self.identity, self.binaries)

    def test_rejects_changed_binary_size(self) -> None:
        self.binaries["/usr/libexec/afcd"]["size"] += 1
        with self.assertRaisesRegex(RuntimeError, "afcd.*size expected"):
            install_device.validate_compatibility(
                self.identity, self.binaries, shared_caches=self.caches
            )

    def test_preflight_returns_verified_evidence(self) -> None:
        cache = install_device._DEFAULT_PROFILE["dyld_shared_caches"]
        with (mock.patch.object(
                install_device, "system_binary_identities", return_value=self.binaries),
              mock.patch.object(
                install_device, "dyld_shared_cache_identities", return_value=cache)):
            result = install_device.compatibility_preflight({}, self.identity)
        self.assertEqual(result["result"], "EXACT_BUILD_MATCH")
        self.assertEqual(result["system_binaries"], self.binaries)

    def test_device_probe_parses_the_pinned_macho_inputs(self) -> None:
        inputs = SCRIPT.parents[1] / "inputs"
        files = {
            str(inputs / "lockdownd-iPhone13,2-24A5390f"):
                install_device.SYSTEM_BINARIES["/usr/libexec/lockdownd"],
            str(inputs / "afcd-iPhone13,2-24A5390f"):
                install_device.SYSTEM_BINARIES["/usr/libexec/afcd"],
        }
        if not all(Path(path).is_file() for path in files):
            self.skipTest("device-derived pinned inputs are not present")

        def ssh(command: str, **kwargs):
            arguments = shlex.split(command)
            self.assertEqual(arguments[:2], ["/var/jb/usr/bin/python3", "-c"])
            return subprocess.run(
                [sys.executable, "-c", arguments[2]],
                capture_output=True,
                check=False,
            )

        with mock.patch.object(install_device, "SYSTEM_BINARIES", files):
            observed = install_device.system_binary_identities({"ssh": ssh})
        for path, expected in files.items():
            self.assertEqual(observed[path]["uuid"], expected["uuid"])
            self.assertEqual(observed[path]["sha256"], expected["sha256"])

    def test_preflight_selects_the_se_profile_by_exact_binary_identity(self) -> None:
        profiles = install_device.load_profiles(install_device.DEFAULT_PROFILE_DIR)
        selected = next(
            profile for profile in profiles
            if profile["device"]["product"] == "iPhone12,8"
        )
        binaries = selected["system_binaries"]
        with (mock.patch.object(
                install_device, "system_binary_identities", return_value=binaries),
              mock.patch.object(
                install_device, "dyld_shared_cache_identities",
                return_value=selected["dyld_shared_caches"])):
            result = install_device.compatibility_preflight(
                {}, selected["device"], profiles
            )
        self.assertEqual(result["profile"]["device"]["product"], "iPhone12,8")
        self.assertEqual(result["result"], "EXACT_BUILD_MATCH")

    def test_preflight_disables_a_failed_offset_profile(self) -> None:
        profile = copy.deepcopy(install_device._DEFAULT_PROFILE)
        profile["offsets"]["cf_runloop_return"]["validation"]["result"] = "FAIL"
        with self.assertRaisesRegex(RuntimeError, "INVALID_COMPATIBILITY_PROFILE"):
            install_device.compatibility_preflight({}, self.identity, [profile])


if __name__ == "__main__":
    unittest.main()
