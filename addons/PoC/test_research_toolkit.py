from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import plistlib
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bridge/DeviceRuntime"))
from zero_sky_core import research_toolkit as toolkit
from zero_sky_core import research_toolkit_device as device
from zero_sky_core import research_toolkit_runner as runner
from zero_sky_core.runtime import CoreRuntime
from zero_sky_core.sensors.recovery import PackageInventory


class FixturePaths:
    def __init__(self, root: Path): self.root = root
    def jailbreak(self, suffix): return self.root / "var/jb" / suffix.lstrip("/")
    def system(self, suffix): return self.root / suffix.lstrip("/")


class ToolkitModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = toolkit.load_catalog()
        cls.rows = {item["id"]: item for item in cls.catalog["components"]}

    def test_overall_result_keeps_smoke_failure_when_uat_is_skipped(self):
        self.assertEqual(runner.overall_result({"result": "FAIL"},
                                               {"result": "DEGRADED"}), "FAIL")
        self.assertEqual(runner.overall_result({"result": "PASS"},
                                               {"result": "DEGRADED"}), "DEGRADED")
        self.assertEqual(runner.overall_result({"result": "UNEXPECTED"},
                                               {"result": "INVALID"}), "BLOCKED")

    def test_manifest_and_classification(self):
        self.assertEqual(len(self.rows), len(self.catalog["components"]))
        self.assertEqual(self.rows["objection"]["scope"], "HOST")
        self.assertEqual(self.rows["objection"]["type"], "HOST_TOOL")
        self.assertEqual(self.rows["ellekit"]["type"], "FRAMEWORK")
        self.assertEqual(self.rows["filza"]["type"], "APP")
        self.assertTrue(all(item["upstream_project"] is None or
                            item["upstream_project"].startswith("https://")
                            for item in self.rows.values()))
        self.assertEqual(self.rows["catvnc"]["package_identifier"], "com.catvnc.server")
        self.assertIsNone(self.rows["catvnc"]["upstream_project"])
        self.assertEqual(self.rows["ldid"]["source_git"], "git://git.saurik.com/ldid.git")
        self.assertEqual(self.rows["mitmproxy"]["upstream_project"],
                         "https://github.com/mitmproxy/mitmproxy")
        self.assertEqual(self.rows["mitmproxy"]["source_release"], "v12.2.3")
        self.assertEqual(self.rows["trolldecrypt"]["bundle_ids"],
                         ["com.fiore.trolldecrypt"])
        self.assertEqual(self.rows["trolldecrypt_0sky"]["bundle_ids"],
                         ["com.liquidsky.TrollDecryptResearch"])
        self.assertEqual(self.rows["trolldecrypt_0sky"]["trust_state"], "LOCAL_0SKY")
        self.assertEqual(self.rows["ssl_kill_switch_3"]["bundle_ids"], [])

    def test_unapproved_git_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "catalog.json"
            altered = copy.deepcopy(self.catalog)
            row = next(item for item in altered["components"] if item["id"] == "ldid")
            row["source_git"] = "git://example.com/ldid.git"
            path.write_text(json.dumps(altered))
            with self.assertRaises(toolkit.ManifestError):
                toolkit.load_catalog(path)
            row["source_git"] = "git://git.saurik.com/ldid.git"
            row["source_git_revision"] = "not-a-commit"
            path.write_text(json.dumps(altered))
            with self.assertRaises(toolkit.ManifestError):
                toolkit.load_catalog(path)

    def test_registered_app_uses_build_when_short_version_is_absent(self):
        with tempfile.TemporaryDirectory() as folder:
            app = Path(folder) / "TrollDecrypt.app"
            app.mkdir()
            (app / "TrollDecrypt").write_bytes(b"binary fixture")
            (app / "Info.plist").write_bytes(plistlib.dumps({
                "CFBundleIdentifier": "com.fiore.trolldecrypt",
                "CFBundleExecutable": "TrollDecrypt",
                "CFBundleVersion": "1.2.4",
            }))
            listing = type("Result", (), {"returncode": 0,
                "stdout": f"com.fiore.trolldecrypt : {app}\n"})()
            detail = type("Result", (), {"returncode": 0,
                "stdout": f"Bundle Identifier: com.fiore.trolldecrypt\n"
                          f"Executable Name: TrollDecrypt\nPath: {app}\n"})()
            with patch.object(device, "APP_ROOTS", (folder + "/", str(Path(folder).resolve()) + "/")), \
                    patch.object(device.subprocess, "run", side_effect=[listing, detail]):
                apps = device.registered_apps()
            self.assertEqual(apps["com.fiore.trolldecrypt"]["version"], "1.2.4")

            placeholder = type("Result", (), {"returncode": 0,
                "stdout": f"Bundle Identifier: com.fiore.trolldecrypt\n"
                          f"Executable Name: (null)\nPath: {app}\n"})()
            with patch.object(device, "APP_ROOTS", (folder + "/", str(Path(folder).resolve()) + "/")), \
                    patch.object(device.subprocess, "run", side_effect=[listing, placeholder]):
                self.assertNotIn("com.fiore.trolldecrypt", device.registered_apps())

    def test_virtual_package_provider_satisfies_dependency(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = FixturePaths(Path(folder))
            status = paths.jailbreak("/Library/dpkg/status")
            status.parent.mkdir(parents=True)
            status.write_text(
                "Package: ellekit\nStatus: install ok installed\nVersion: 1.2\n"
                "Provides: mobilesubstrate (= 99)\n\n"
                "Package: com.catvnc.server\nStatus: install ok installed\nVersion: 0.0.2\n"
                "Depends: mobilesubstrate, preferenceloader\n\n"
                "Package: preferenceloader\nStatus: install ok installed\nVersion: 2.4.3\n\n")
            rows = {row["package"]: row for row in PackageInventory(paths).collect(10)}
            self.assertEqual(rows["com.catvnc.server"]["missingDependencies"], [])
            self.assertIn("com.catvnc.server", rows["ellekit"]["reverseDependencies"])
            status.write_text(status.read_text().replace("Provides: mobilesubstrate (= 99)\n", ""))
            rows = {row["package"]: row for row in PackageInventory(paths).collect(10)}
            self.assertEqual(rows["com.catvnc.server"]["missingDependencies"],
                             [["mobilesubstrate"]])

    def test_injection_quarantine_is_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = FixturePaths(Path(folder))
            runtime = paths.jailbreak("/var/lib/srd-runtime")
            runtime.mkdir(parents=True)
            (runtime / "registry.json").write_text(json.dumps({"targets": {
                "/usr/libexec/backboardd": {"name": "com.apple.backboardd",
                    "dylibs": [{"path": "/var/jb/Library/MobileSubstrate/DynamicLibraries/catvnc.dylib",
                        "sha256": "fixture", "package": "com.catvnc.server"}]}}}))
            (runtime / "injection-state.json").write_text(json.dumps({"loaded": {}}))
            (runtime / "injection-quarantine.json").write_text(json.dumps({"entries": {
                "fixture": {"package": "com.catvnc.server", "target": "com.apple.backboardd",
                    "reason": "loader failed while target remained alive"}}}))
            evidence = device.injection_evidence(paths)
            self.assertEqual(evidence["com.catvnc.server"]["runtime"], "FAIL")
            self.assertIn("loader failed", evidence["com.catvnc.server"]["reason"])

    def test_duplicate_and_cycle_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "catalog.json"
            altered = copy.deepcopy(self.catalog)
            altered["components"].append(copy.deepcopy(altered["components"][0]))
            path.write_text(json.dumps(altered))
            with self.assertRaises(toolkit.ManifestError):
                toolkit.load_catalog(path)
            altered = copy.deepcopy(self.catalog)
            by_id = {item["id"]: item for item in altered["components"]}
            by_id["filza"]["dependencies"] = ["frida"]
            by_id["frida"]["dependencies"].append("filza")
            path.write_text(json.dumps(altered))
            with self.assertRaises(toolkit.ManifestError):
                toolkit.load_catalog(path)

    def test_source_trust_and_hash(self):
        with tempfile.TemporaryDirectory() as folder:
            artifact = Path(folder) / "package.deb"
            artifact.write_bytes(b"reviewed artifact")
            pinned = hashlib.sha256(artifact.read_bytes()).hexdigest()
            self.assertEqual(toolkit.verify_artifact(artifact, None)["result"], "UNVERIFIED")
            self.assertEqual(toolkit.verify_artifact(artifact, pinned)["result"], "PASS")
            artifact.write_bytes(b"changed bytes")
            self.assertEqual(toolkit.verify_artifact(artifact, pinned)["result"], "BLOCKED")

    def test_ios_27_requires_exact_validation(self):
        row = self.rows["ssl_kill_switch_3"]
        unknown = toolkit.compatibility_for(row, ios_version="27.0", architecture="arm64",
                                            root_model="rootless")
        self.assertEqual(unknown["result"], "UNKNOWN")
        checked = toolkit.compatibility_for(row, ios_version="27.0", architecture="arm64",
                                            root_model="rootless",
                                            runtime_evidence={"os_version": "27.0", "result": "PASS"})
        self.assertEqual(checked["result"], "COMPATIBLE")
        wrong = toolkit.compatibility_for(row, ios_version="27.0", architecture="x86_64",
                                          root_model="rootless")
        self.assertEqual(wrong["result"], "BLOCKED_BY_ARCHITECTURE")

    def test_trollstore_upstream_ceiling_blocks_ios_27(self):
        row = self.rows["trollstore"]
        self.assertEqual(row["maximum_ios"], "17.0")
        self.assertEqual(toolkit.compatibility_for(
            row, ios_version="27.0", architecture="arm64e", root_model="rootless",
            runtime_evidence={"os_version": "27.0", "result": "PASS"})["result"],
            "ADAPTATION_REQUIRED")
        self.assertEqual(toolkit.compatibility_for(
            row, ios_version="17.0", architecture="arm64", root_model="rootless")["result"],
            "UNKNOWN")

    def test_doodle_adaptation_is_exact_and_not_upstream_admission(self):
        manifest = json.loads((Path(__file__).resolve().parents[2] /
            "compat/ios27/doodle/0sky-compat.json").read_text())
        variant = self.rows["doodle"]["adapted_variants"][0]
        self.assertEqual(variant["package_version"], manifest["private_package_version"])
        self.assertEqual(variant["dylib_sha256"], manifest["resulting_artifact_sha256"])
        self.assertEqual({(target["model"], target["ios_build"])
            for target in variant["verified_targets"]},
            {(target["model"], target["build"])
             for target in manifest["verified_targets"]})
        self.assertEqual(toolkit.compatibility_for(
            self.rows["doodle"], ios_version="27.0", architecture="arm64e",
            root_model="rootless")["result"], "ADAPTATION_REQUIRED")
        with tempfile.TemporaryDirectory() as folder:
            paths = FixturePaths(Path(folder))
            row = copy.deepcopy(self.rows["doodle"])
            dylib = paths.jailbreak(row["adapted_variants"][0]["dylib_path"])
            dylib.parent.mkdir(parents=True)
            dylib.write_bytes(b"adapted fixture")
            digest = hashlib.sha256(dylib.read_bytes()).hexdigest()
            row["adapted_variants"][0]["dylib_sha256"] = digest
            root = paths.jailbreak("/var/lib/srd-runtime")
            root.mkdir(parents=True)
            (root / "registry.json").write_text('{"quarantined":[]}')
            (root / "injection-state.json").write_text(json.dumps({"loaded": {"one": {
                "pid": 123, "sha256": digest, "dylib": str(dylib)}}}))
            receipt = Path(folder) / "receipt.plist"
            checked = {key: True for key in ("native_authentication", "pattern_unlock",
                "wrong_pattern_rejected", "keypad_fallback", "repeat_pattern_unlock",
                "springboard_stable")}
            receipt.write_bytes(plistlib.dumps({"schema": 1,
                "package_version": variant["package_version"],
                "dylib_sha256": digest, "device_model": "iPhone13,2",
                "ios_build": "24A5390f",
                "verified_at": time.time(), **checked}))
            fake_ps = lambda *_args, **_kwargs: SimpleNamespace(
                returncode=0, stdout="123 /System/Library/CoreServices/SpringBoard.app/SpringBoard\n")
            found = device.adapted_tweak_evidence(paths, row,
                {"version": variant["package_version"]}, "24A5390f", "iPhone13,2",
                receipt_override=receipt, process_run=fake_ps)
            self.assertEqual(found["compatibility"], "COMPATIBLE_WITH_ADAPTER")
            self.assertEqual(found["runtime"], "PASS")
            self.assertFalse(row["package_source_trust"] == "OFFICIAL")
            stale = plistlib.loads(receipt.read_bytes())
            stale["verified_at"] = time.time() - 100 * 86400
            receipt.write_bytes(plistlib.dumps(stale))
            old = device.adapted_tweak_evidence(paths, row,
                {"version": variant["package_version"]}, "24A5390f", "iPhone13,2",
                receipt_override=receipt, process_run=fake_ps)
            self.assertEqual(old["compatibility"], "COMPATIBLE_WITH_ADAPTER")
            self.assertEqual(old["runtime"], "UNTESTED")
            self.assertIsNone(device.adapted_tweak_evidence(paths, row,
                {"version": "1.2"}, "24A5390f", "iPhone13,2", receipt_override=receipt,
                process_run=fake_ps))
            self.assertIsNone(device.adapted_tweak_evidence(paths, row,
                {"version": variant["package_version"]}, "24A5390f", "iPhone99,1",
                receipt_override=receipt, process_run=fake_ps))
            dylib.write_bytes(b"changed")
            self.assertIsNone(device.adapted_tweak_evidence(paths, row,
                {"version": variant["package_version"]}, "24A5390f", "iPhone13,2",
                receipt_override=receipt, process_run=fake_ps))

    def test_adapted_variant_rejects_unsafe_manifest_path(self):
        value = copy.deepcopy(self.catalog)
        doodle = next(row for row in value["components"] if row["id"] == "doodle")
        doodle["adapted_variants"][0]["dylib_path"] = "/Library/../private/unsafe.dylib"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "catalog.json"
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(toolkit.ManifestError, "adapted variant"):
                toolkit.load_catalog(path)

    def test_dependency_and_state_gates(self):
        row = self.rows["choicy"]
        missing = toolkit.resolve_dependencies(row, {})
        self.assertEqual(set(missing["missing"]), {"ellekit", "preferenceloader"})
        observation = {"source": "PASS", "compatibility": "COMPATIBLE",
                       "installation": "INSTALLED", "configured": True,
                       "runtime": "PASS", "smoke": "PASS", "uat": "PASS"}
        self.assertEqual(toolkit.classify(row, observation, missing)["badge"], "MISSING DEPENDENCY")
        passed = toolkit.resolve_dependencies(row, {
            "ellekit": {"installation": "INSTALLED"},
            "preferenceloader": {"installation": "INSTALLED"}})
        self.assertEqual(toolkit.classify(row, observation, passed)["badge"], "READY")
        for facet, state in (("source", "UNVERIFIED"), ("compatibility", "UNVERIFIED"),
                             ("runtime", "FAIL"), ("smoke", "FAIL"), ("uat", "SKIP")):
            changed = {**observation, facet: state}
            self.assertNotEqual(toolkit.classify(row, changed, passed)["badge"], "READY")

    def test_failed_installed_tweak_can_still_offer_authenticated_remove(self):
        row = self.rows["catvnc"]
        dependencies = toolkit.resolve_dependencies(row, {
            "ellekit": {"installation": "INSTALLED"},
            "preferenceloader": {"installation": "INSTALLED"},
        })
        classified = toolkit.classify(row, {
            "source": "UNVERIFIED", "compatibility": "ADAPTATION_REQUIRED",
            "installation": "INSTALLED", "configured": False,
            "runtime": "FAIL", "smoke": "SKIP", "uat": "SKIP",
            "installer_ready": True,
        }, dependencies)
        self.assertIn("remove", classified["actions"])
        self.assertEqual(classified["badge"], "ADAPTATION REQUIRED")

    def test_illegal_lifecycle_transition(self):
        self.assertEqual(toolkit.transition("INSTALLED", "CONFIGURED"), "CONFIGURED")
        with self.assertRaises(ValueError):
            toolkit.transition("INSTALLED", "READY")

    def test_device_discovery_keeps_installed_separate_from_ready(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = FixturePaths(Path(folder))
            paths.jailbreak("/").mkdir(parents=True)
            with patch("zero_sky_core.research_toolkit_device._sysctl_integer",
                       side_effect=[0x0100000C, 2]):
                result = device.collect(paths, catalog=self.catalog,
                                    package_rows=[{"package": "com.opa334.choicy",
                                                   "version": "1.0", "health": "Healthy"}],
                                    apps={"com.tigisoftware.Filza": {"path": "/safe/Filza.app",
                                                                         "version": "4.0"}},
                                    host={"connected": False, "tools": {}},
                                    ios_version="27.0", architecture="iPhone12,8")
            rows = {row["id"]: row for row in result["components"]}
            self.assertEqual(result["environment"]["architecture"], "arm64e")
            self.assertTrue(result["environment"]["architecture_verified"])
            self.assertEqual(rows["filza"]["facets"]["installation"], "INSTALLED")
            self.assertNotEqual(rows["filza"]["badge"], "READY")
            self.assertEqual(rows["choicy"]["facets"]["installation"], "INSTALLED")
            self.assertEqual(rows["choicy"]["badge"], "MISSING DEPENDENCY")
            self.assertEqual(rows["objection"]["scope"], "HOST")

    def test_launchservices_outage_does_not_mark_apps_absent(self):
        with tempfile.TemporaryDirectory() as folder:
            paths = FixturePaths(Path(folder))
            paths.jailbreak("/").mkdir(parents=True)
            with patch.object(device, "registered_apps", side_effect=RuntimeError("unavailable")):
                result = device.collect(paths, catalog=self.catalog, package_rows=[],
                                        host={"connected": False, "tools": {}},
                                        ios_version="27.0", architecture="arm64e")
            rows = {row["id"]: row for row in result["components"]}
            self.assertEqual(result["environment"]["app_discovery_status"], "UNAVAILABLE")
            self.assertEqual(rows["filza"]["facets"]["installation"], "UNKNOWN")
            self.assertEqual(rows["filza"]["badge"], "UNTESTED")
            class Probes:
                def package_database(self): return {"status": 0, "output": "", "apt_check_status": 0}
                def command_version(self, _executable): return {"status": 0, "output": "1.0"}
                def local_bridge(self): return True
            smoke = runner.run_smoke(result, Probes())
            self.assertEqual(next(row for row in smoke["tests"] if row["id"] == "SMOKE-10")["result"],
                             "BLOCKED")

    def test_failed_gui_launch_is_visible_as_failure(self):
        row = self.rows["filza"]
        dependencies = {"result": "PASS", "missing": [], "conflicts": []}
        absent = toolkit.classify(row, {"source": "UNVERIFIED",
                                      "installation": "NOT_INSTALLED"}, dependencies)
        self.assertEqual(absent["lifecycle_stage"], "DISCOVER")
        failed = toolkit.classify(row, {"source": "PASS", "compatibility": "UNVERIFIED",
                                      "installation": "INSTALLED", "runtime": "FAIL",
                                      "runtime_reason": "SIGKILL - CODESIGNING"}, dependencies)
        self.assertEqual(failed["badge"], "REPAIR REQUIRED")
        self.assertEqual(failed["runtime_reason"], "SIGKILL - CODESIGNING")

        partial = toolkit.classify(self.rows["sileo"],
                                   {"source": "UNVERIFIED", "compatibility": "UNVERIFIED",
                                    "installation": "PARTIAL", "registration": "FAIL",
                                    "runtime_reason": "LaunchServices has no verified app"},
                                   dependencies)
        self.assertEqual(partial["badge"], "REPAIR REQUIRED")
        self.assertEqual(partial["facets"]["installation"], "PARTIAL")
        self.assertIn("LaunchServices", partial["runtime_reason"])

        class Probes:
            def package_database(self): return {"status": 0, "output": "", "apt_check_status": 0}
            def command_version(self, _executable): return {"status": 0, "output": "1.0"}
            def local_bridge(self): return True

        snapshot = {"components": [failed], "environment": {"ios_version": "27.0",
            "device_model": "iPhone12,8", "architecture": "arm64e",
            "architecture_verified": True, "bootstrap": "rootless", "host_connected": True}}
        smoke = runner.run_smoke(snapshot, Probes())
        gui_case = next(case for case in smoke["tests"] if case["id"] == "SMOKE-10")
        self.assertEqual(gui_case["result"], "FAIL")
        self.assertIn("filza", gui_case["observed"])

    def test_stale_host_heartbeat_cannot_claim_detection(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "heartbeat.json"
            path.write_text(json.dumps({"timestamp": 0,
                "host_tools": {"objection": {"detected": True}},
                "apple_pairing_verified": True, "lockdown_session_validated": True,
                "host_identity_verified": True}))
            self.assertFalse(device.host_status(path)["connected"])

    def test_ssh_smoke_requires_fresh_paired_host_evidence(self):
        class Probes:
            def package_database(self):
                return {"status": 0, "output": "", "apt_check_status": 0}
            def command_version(self, _executable):
                return {"status": 0, "output": "1.0"}
            def local_bridge(self):
                return True

        snapshot = {"components": [], "environment": {"ios_version": "27.0",
            "device_model": "iPhone13,2", "architecture": "arm64e",
            "architecture_verified": True, "bootstrap": "rootless",
            "host_connected": True, "ssh_uat": {"result": "PASS", "transport": "configured"}}}
        result = runner.run_smoke(snapshot, Probes())
        case = next(row for row in result["tests"] if row["id"] == "SMOKE-14")
        self.assertEqual(case["result"], "PASS")
        snapshot["environment"]["ssh_uat"] = {"result": "UNVERIFIED"}
        result = runner.run_smoke(snapshot, Probes())
        case = next(row for row in result["tests"] if row["id"] == "SMOKE-14")
        self.assertEqual(case["result"], "DEGRADED")

    def test_device_rejects_stale_paired_ssh_evidence(self):
        checks = ["usb_identity", "pinned_public_key", "root_shell",
                  "server_process", "localhost_listener", "file_round_trip",
                  "cleanup", "reconnect"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "heartbeat.json"
            heartbeat = {"timestamp": time.time(), "apple_pairing_verified": True,
                         "lockdown_session_validated": True, "host_identity_verified": True,
                         "host_tools": {}, "ssh_uat": {"result": "PASS",
                         "checked_at": int(time.time()), "transport": "configured",
                         "checks": checks}}
            path.write_text(json.dumps(heartbeat))
            self.assertEqual(device.host_status(path)["ssh_uat"]["result"], "PASS")
            heartbeat["ssh_uat"]["checked_at"] -= 7200
            path.write_text(json.dumps(heartbeat))
            self.assertEqual(device.host_status(path)["ssh_uat"]["result"], "UNVERIFIED")

    def test_frida_enumeration_evidence_never_completes_controlled_uat(self):
        class Probes:
            def package_database(self): return {"status": 0, "output": "", "apt_check_status": 0}
            def command_version(self, _executable): return {"status": 0, "output": "1.0"}
            def local_bridge(self): return True

        checks = ["usb_identity", "artifact_hash", "server_process",
                  "localhost_listener", "host_version", "process_enumeration"]
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "heartbeat.json"
            heartbeat = {"timestamp": time.time(), "apple_pairing_verified": True,
                         "lockdown_session_validated": True, "host_identity_verified": True,
                         "host_tools": {}, "frida_uat": {"result": "PASS",
                         "checked_at": int(time.time()), "host_version": "17.18.0",
                         "device_version": "17.18.0", "scope": "read_only_process_enumeration",
                         "transport": "exact_usb_iproxy", "checks": checks}}
            path.write_text(json.dumps(heartbeat))
            self.assertEqual(device.host_status(path)["frida_uat"]["result"], "PASS")
            heartbeat["frida_uat"]["checked_at"] -= 7200
            path.write_text(json.dumps(heartbeat))
            self.assertEqual(device.host_status(path)["frida_uat"]["result"], "UNVERIFIED")
            heartbeat["frida_uat"]["checked_at"] = int(time.time())
            heartbeat["frida_uat"]["scope"] = "arbitrary_app_attach"
            path.write_text(json.dumps(heartbeat))
            self.assertEqual(device.host_status(path)["frida_uat"]["result"], "UNVERIFIED")

        installed = lambda component: {"id": component, "type": "INSTRUMENTATION",
                                       "missing_dependencies": [],
                                       "facets": {"installation": "INSTALLED",
                                                  "source": "PASS", "compatibility": "COMPATIBLE",
                                                  "runtime": "DEGRADED"}}
        snapshot = {"components": [installed("frida_server"), installed("frida_cli")],
                    "environment": {"ios_version": "27.0", "device_model": "iPhone13,2",
                        "architecture": "arm64e", "architecture_verified": True,
                        "bootstrap": "rootless", "host_connected": True,
                        "frida_uat": {"result": "PASS"}}}
        smoke = runner.run_smoke(snapshot, Probes())
        frida_case = next(row for row in smoke["tests"] if row["id"] == "SMOKE-12")
        self.assertEqual(frida_case["result"], "DEGRADED")
        self.assertIn("process enumeration passed", frida_case["observed"])
        uat = runner.run_uat(snapshot, smoke)
        self.assertEqual(uat["tests"][8]["result"], "SKIP")

    def test_smoke_and_uat_keep_unperformed_cases_visible(self):
        class Probes:
            def package_database(self): return {"status": 0, "output": ""}
            def command_version(self, executable): return {"status": 0, "output": "1.0"}
            def local_bridge(self): return True

        with tempfile.TemporaryDirectory() as folder:
            paths = FixturePaths(Path(folder))
            paths.jailbreak("/").mkdir(parents=True)
            snapshot = device.collect(paths, catalog=self.catalog, package_rows=[], apps={},
                host={"connected": False, "tools": {}}, ios_version="27.0", architecture="arm64")
            smoke = runner.run_smoke(snapshot, Probes())
            uat = runner.run_uat(snapshot, smoke)
            self.assertEqual(len(smoke["tests"]), 17)
            self.assertEqual(len(uat["tests"]), 12)
            self.assertEqual(uat["tests"][0]["result"], "SKIP")
            self.assertNotEqual(uat["result"], "PASS")
            bundle = runner.write_bundle(Path(folder) / "evidence", snapshot, smoke, uat)
            self.assertTrue((bundle / "summary.json").is_file())
            self.assertEqual(json.loads((bundle / "uat-results.json").read_text())["counts"]["SKIP"], 12)

    def test_uat_pass_requires_evidence(self):
        result = runner.run_uat({}, {}, {"ui_apps": {"result": "PASS"}})
        self.assertEqual(result["tests"][0]["result"], "FAIL")

    def test_virtual_package_audit_is_warning_when_apt_check_passes(self):
        text = ("The following packages are missing the md5sums control file in the\n"
                "database, they need to be reinstalled:\n"
                " cy+cpu.arm64 virtual CPU dependency\n"
                " gsc.64-bit virtual GraphicsServices dependency\n"
                " firmware almost impressive Apple frameworks\n")
        class Probes:
            def package_database(self):
                return {"status": 0, "output": text, "apt_check_status": 0}
            def command_version(self, executable):
                return {"status": 0, "output": "1.0"}
            def local_bridge(self):
                return True
        snapshot = toolkit.evaluate(self.catalog, {})
        snapshot["environment"] = {"ios_version": "27.0", "architecture": "arm64",
                                   "architecture_verified": False, "bootstrap": "rootless"}
        smoke = runner.run_smoke(snapshot, Probes())
        self.assertEqual(smoke["tests"][2]["result"], "DEGRADED")
        self.assertNotEqual(smoke["result"], "PASS")

    def test_ipc_sensor_recovers_once_per_failure(self):
        runtime = CoreRuntime.__new__(CoreRuntime)
        runtime._core_ipc_recovered = False
        with patch.object(CoreRuntime, "sensor_success") as sensor_success:
            self.assertTrue(runtime._ipc_success("one", {})["success"])
            self.assertTrue(runtime._ipc_success("two", {})["success"])
            sensor_success.assert_called_once_with("core_ipc")
            runtime._core_ipc_recovered = False
            self.assertTrue(runtime._ipc_success("three", {})["success"])
            self.assertEqual(sensor_success.call_count, 2)


if __name__ == "__main__":
    unittest.main()
