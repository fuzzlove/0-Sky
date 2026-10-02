import hashlib
import io
import json
from pathlib import Path
import plistlib
import shutil
import struct
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

from tools.ios27_compat_pipeline import (admission, conversion_plan, deb_contents_type, deb_fields,
                                         deb_control_members, entitlement_evidence,
                                         inspect_item, parse_dependency_groups, resolve_graph, sanitize,
                                         scan, source_catalog, stable_id,
                                         validate_compat_manifest, write_reports, REQUIRED_GATE)
from zero_sky_compat.model import Environment
from zero_sky_compat.paths import RootlessPaths
from zero_sky_compat import macho
from zero_sky_compat.registry import Registry
from zero_sky_core.research_toolkit import ManifestError, compatibility_for, load_catalog
from compat.ios27.doodle.runtime_probe import (classify as classify_doodle_api,
                                                classify_hook_surface)
from compat.ios27.candidates import load_candidate_pins


class CompatibilityPipelineTests(unittest.TestCase):
    def test_stable_identifier_and_paths_are_relative(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "components" / "helper.sh"
            path.parent.mkdir()
            path.write_text("#!/bin/sh\n/usr/bin/id\n")
            row = inspect_item(root, path)
            self.assertEqual(row["path"], "components/helper.sh")
            self.assertEqual(row["id"], stable_id("components/helper.sh"))
            self.assertEqual(row["type"], "SOURCE")
            self.assertEqual(row["status"], "UNVERIFIED")

    def test_rootless_translation_requires_exact_owned_path(self):
        env = Environment(ios_version="27.0", architecture="arm64", bootstrap_prefix="/var/jb",
                          capabilities={"var_jb": True})
        paths = RootlessPaths.from_environment(env)
        self.assertEqual(paths.OSKY_APPLICATIONS, "/var/jb/Applications")
        self.assertEqual(paths.translate_owned("/Library/LaunchDaemons/test.plist",
                         {"/Library/LaunchDaemons/test.plist"}),
                         "/var/jb/Library/LaunchDaemons/test.plist")
        self.assertEqual(paths.translate_owned("/var/jb/Library/LaunchDaemons/test.plist", set()),
                         "/var/jb/Library/LaunchDaemons/test.plist")
        with self.assertRaisesRegex(ValueError, "not declared"):
            paths.translate_owned("/System/Library/PrivateFrameworks/X", set())

    def test_three_matching_failures_quarantine_only_same_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            registry = Registry(Path(directory) / "registry.sqlite3")
            for attempt in range(1, 4):
                evidence = registry.record_component_failure("artifact-a", "dyld missing symbol X")
                self.assertEqual(evidence["count"], attempt)
            self.assertTrue(registry.quarantined("artifact-a"))
            self.assertFalse(registry.quarantined("artifact-b"))

    def test_developer_path_is_redacted_and_blocks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "Makefile"
            path.write_text("SOURCE=/" + "Users/developer/private/signing-key.p12\n")
            row = inspect_item(root, path)
            self.assertIn("DEVELOPER_PATH_REVIEW", row["issues"])
            self.assertNotIn("developer", json.dumps(row))
            self.assertEqual(row["status"], "BLOCKED")

    def test_nested_binary_metadata_redaction(self):
        host_path = "/" + "Users" + "/alice/build/lib"
        value = sanitize({"slices": [{"rpath": host_path}]})
        self.assertNotIn("alice", json.dumps(value))
        build_path = "/" + "Users" + "/alice/Library/Developer/Xcode/" + "Derived" + "Data/project/Build/file"
        build = sanitize({"path": build_path})
        self.assertNotIn("Derived" + "Data/", json.dumps(build))
        self.assertNotIn("alice", json.dumps(build))

    def test_bad_daemon_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "Library/LaunchDaemons/bad.plist"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"not a plist")
            row = inspect_item(root, path)
            self.assertIn("PLIST_INVALID", row["issues"])
            self.assertEqual(row["type"], "DAEMON")

    def test_unsigned_binary_entitlement_report_is_explicit(self):
        row = {"id": "unsigned", "path": "missing", "signature_present": False}
        self.assertEqual(entitlement_evidence(Path("/missing"), row)["state"],
                         "SIGNATURE_ABSENT")

    def test_large_macho_load_commands_are_streamed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large-tool"
            with path.open("wb") as stream:
                stream.write(struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0))
                stream.truncate(70 * 1024 * 1024)
            self.assertEqual(macho.parse(path)[0]["architecture"], "arm64")

    def test_source_api_candidates_remain_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "hook.m"
            source.write_text('id cls = NSClassFromString(@"SBUnknownController");\n'
                              'SEL sel = NSSelectorFromString(@"privateAction:");\n')
            row = inspect_item(root, source)
            self.assertIn(("class", "SBUnknownController"), row["api_references"])
            self.assertIn(("selector", "privateAction:"), row["api_references"])
            self.assertEqual(row["status"], "UNVERIFIED")

    def test_dependency_order_cycle_and_missing(self):
        a = {"id": "a", "package": {"Package": "a"}, "dependencies": ["b"]}
        b = {"id": "b", "package": {"Package": "b"}, "dependencies": []}
        graph = resolve_graph([a, b])
        self.assertEqual(graph["build_order"], ["b", "a"])
        a["dependencies"] = ["b", "missing"]
        b["dependencies"] = ["a"]
        graph = resolve_graph([a, b])
        self.assertEqual(graph["cycles"], ["a", "b"])
        self.assertEqual(graph["missing"][0]["package"], "missing")

    def test_dependency_parser_preserves_alternatives_and_predepends(self):
        parsed = parse_dependency_groups("ellekit (>= 1.2) | mobilesubstrate, dpkg:any (>= 1.20)")
        self.assertEqual(parsed[0][0], {"name": "ellekit", "qualifier": None,
                                        "operator": ">=", "version": "1.2"})
        self.assertEqual(parsed[0][1]["name"], "mobilesubstrate")
        self.assertEqual(parsed[1][0]["qualifier"], "any")
        with self.assertRaises(ValueError):
            parse_dependency_groups("ellekit [arm64]")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "sample.deb"
            package.write_bytes(b"fixture")
            fields = {"Package": "sample", "Version": "1", "Architecture": "iphoneos-arm64",
                      "Pre-Depends": "dpkg (>= 1.20)", "Depends": "ellekit | mobilesubstrate"}
            with mock.patch("tools.ios27_compat_pipeline.deb_fields", return_value=fields), \
                 mock.patch("tools.ios27_compat_pipeline.deb_contents_type", return_value=("TWEAK", [])):
                row = inspect_item(root, package)
            self.assertEqual([group["kind"] for group in row["dependency_groups"]],
                             ["Pre-Depends", "Depends"])
            self.assertEqual(row["dependencies"], ["dpkg", "ellekit", "mobilesubstrate"])

    @unittest.skipUnless(shutil.which("dpkg"), "dpkg version comparator unavailable")
    def test_alternative_dependency_uses_satisfied_version(self):
        consumer = {"id": "consumer", "path": "consumer.deb", "dependencies": [],
                    "dependency_groups": [{"kind": "Depends", "alternatives":
                        parse_dependency_groups("first (>= 2) | second (>= 2)")[0]}],
                    "package": {"Package": "consumer", "Version": "1",
                                "Architecture": "iphoneos-arm64"}}
        first = {"id": "first", "path": "first.deb", "dependencies": [],
                 "package": {"Package": "first", "Version": "1",
                             "Architecture": "iphoneos-arm64"}}
        second = {"id": "second", "path": "second.deb", "dependencies": [],
                  "package": {"Package": "second", "Version": "2",
                              "Architecture": "iphoneos-arm64"}}
        graph = resolve_graph([consumer, first, second])
        self.assertEqual(graph["edges"][0]["package"], "second")
        self.assertEqual(graph["edges"][0]["chosen_alternative"], 1)
        self.assertEqual(graph["missing"], [])
        second["package"]["Version"] = "1"
        blocked = resolve_graph([consumer, first, second])
        self.assertEqual(len(blocked["missing"]), 1)
        self.assertEqual([choice["state"] for choice in blocked["missing"][0]["alternatives"]],
                         ["VERSION_CONFLICT", "VERSION_CONFLICT"])

    def test_unproven_source_stays_blocked_in_conversion_plan(self):
        row = {"id": "one", "path": "one.deb", "type": "TWEAK", "issues": [],
               "dependencies": [], "sha256": "a" * 64,
               "package": {"Package": "unknown.package", "Architecture": "iphoneos-arm64"}}
        plan = conversion_plan([row], resolve_graph([row]), {})
        self.assertEqual(plan[0]["status"], "BUILD_REQUIRED")
        self.assertEqual(plan[0]["repo_admission"], "BLOCKED")

    def test_deb_contents_rejects_traversal_and_symlinks(self):
        prefix = "-rwxr-xr-x root/root 12 2026-09-29 00:00 "
        link = "lrwxrwxrwx root/root 0 2026-09-29 00:00 "
        for listing, issue in (
            (prefix + "./var/jb/../etc/passwd\n", "PACKAGE_UNSAFE_PATH"),
            (link + "./var/jb/usr/lib/test.dylib -> /outside\n",
             "PACKAGE_SYMLINK_REQUIRES_REVIEW"),
        ):
            with self.subTest(issue=issue):
                with mock.patch("tools.ios27_compat_pipeline.subprocess.run",
                                return_value=mock.Mock(returncode=0, stdout=listing)):
                    kind, issues = deb_contents_type(Path("fixture.deb"))
                self.assertEqual(kind, "UNKNOWN")
                self.assertEqual(issues, [issue])
        valid = ("drwxr-xr-x root/root 0 2026-09-29 00:00 ./.\n" +
                 prefix + "./var/jb/Applications/Test.app/Test\n")
        with mock.patch("tools.ios27_compat_pipeline.subprocess.run",
                        return_value=mock.Mock(returncode=0, stdout=valid)):
            self.assertEqual(deb_contents_type(Path("fixture.deb")), ("APP", []))

    def test_deb_contents_reports_all_unsafe_entries(self):
        listing = ("lrwxrwxrwx root/root 0 2026-09-29 00:00 "
                   "./var/jb/../etc/passwd -> /outside\n")
        with mock.patch("tools.ios27_compat_pipeline.subprocess.run",
                        return_value=mock.Mock(returncode=0, stdout=listing)):
            self.assertEqual(deb_contents_type(Path("fixture.deb")),
                             ("UNKNOWN", ["PACKAGE_SYMLINK_REQUIRES_REVIEW", "PACKAGE_UNSAFE_PATH"]))

    def test_deb_metadata_decode_error_fails_closed(self):
        error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")
        with mock.patch("tools.ios27_compat_pipeline.subprocess.run", side_effect=error):
            self.assertEqual(deb_fields(Path("fixture.deb")),
                             {"error": "PACKAGE_METADATA_INVALID"})
            self.assertEqual(deb_contents_type(Path("fixture.deb")),
                             ("UNKNOWN", ["PACKAGE_CONTENTS_INVALID"]))

    def test_deb_control_scripts_are_hashed_and_never_executed(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, data in (("./control", b"Package: fixture\n"),
                               ("./postinst", b"#!/bin/sh\nuicache -p /Applications/Test.app\n")):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        def fake_run(arguments, **kwargs):
            self.assertEqual(arguments[1], "--ctrl-tarfile")
            kwargs["stdout"].write(output.getvalue())
            return mock.Mock(returncode=0)
        entries, issues = deb_control_members(Path("fixture.deb"), run=fake_run)
        self.assertEqual([item["name"] for item in entries], ["control", "postinst"])
        self.assertEqual(entries[1]["sha256"], hashlib.sha256(
            b"#!/bin/sh\nuicache -p /Applications/Test.app\n").hexdigest())
        self.assertEqual(entries[1]["command_references"], ["uicache"])
        self.assertIn("/Applications/Test.app", entries[1]["absolute_paths"])
        self.assertEqual(issues, ["MAINTAINER_SCRIPT_REQUIRES_REVIEW"])

    def test_deb_control_symlink_is_quarantined(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as archive:
            member = tarfile.TarInfo("./postinst")
            member.type = tarfile.SYMTYPE
            member.linkname = "/outside"
            archive.addfile(member)
        def fake_run(_arguments, **kwargs):
            kwargs["stdout"].write(output.getvalue())
            return mock.Mock(returncode=0)
        entries, issues = deb_control_members(Path("fixture.deb"), run=fake_run)
        self.assertEqual(entries, [])
        self.assertEqual(issues, ["PACKAGE_CONTROL_SPECIAL_ENTRY"])

    def test_malformed_archive_is_quarantined_before_source_conversion(self):
        row = {"id": "unsafe", "path": "unsafe.ipa", "type": "APP",
               "issues": ["IPA_UNSAFE_PATH"], "dependencies": [],
               "sha256": "a" * 64, "bundle_id": "com.example.unsafe",
               "architectures": ["arm64"]}
        catalog = {"com.example.unsafe": {
            "upstream_project": "https://example.invalid/unsafe",
            "source_revision": "a" * 40, "license": "MIT", "trust_state": "OFFICIAL"}}
        plan = conversion_plan([row], resolve_graph([row]), catalog)[0]
        self.assertEqual(plan["status"], "UNSAFE_TO_ADAPT")
        self.assertEqual(plan["repo_admission"], "BLOCKED")

    def test_fork_checkout_is_not_labeled_official_upstream(self):
        row = {"id": "sileo", "path": "sileo.deb", "type": "APP", "issues": [],
               "dependencies": [], "sha256": "a" * 64,
               "package": {"Package": "org.coolstar.sileo", "Architecture": "iphoneos-arm64"}}
        plan = conversion_plan([row], resolve_graph([row]), source_catalog())[0]
        self.assertEqual(plan["upstream_project"], "https://github.com/Sileo/Sileo")
        self.assertEqual(plan["source_url"], "https://github.com/fuzzlove/Sileo")
        self.assertEqual(plan["source_trust"], "UNVERIFIED")
        self.assertEqual(plan["status"], "BUILD_REQUIRED")
        self.assertIn("SOURCE_CHECKOUT_UNVERIFIED", plan["blockers"])

    def test_external_checkout_does_not_inherit_local_source_catalog(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(source_catalog(Path(directory)), {})

    def test_source_catalog_symlink_does_not_inherit_other_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bridge/DeviceRuntime/zero_sky_core/research_toolkit_manifest.json"
            path.parent.mkdir(parents=True)
            path.symlink_to(Path(__file__).resolve().parents[2] /
                            "bridge/DeviceRuntime/zero_sky_core/research_toolkit_manifest.json")
            self.assertEqual(source_catalog(Path(directory)), {})
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            checkout = base / "checkout"
            outside = base / "outside"
            outside.mkdir()
            (outside / "research_toolkit_manifest.json").write_bytes(
                (Path(__file__).resolve().parents[2] /
                 "bridge/DeviceRuntime/zero_sky_core/research_toolkit_manifest.json").read_bytes())
            parent = checkout / "bridge/DeviceRuntime"
            parent.mkdir(parents=True)
            (parent / "zero_sky_core").symlink_to(outside)
            self.assertEqual(source_catalog(checkout), {})

    def test_catalog_rejects_package_identity_confusion(self):
        original = load_catalog()
        modified = json.loads(json.dumps(original))
        first = next(row for row in modified["components"] if row.get("package_ids"))
        second = next(row for row in modified["components"] if row["id"] != first["id"])
        second["bundle_ids"] = [first["package_ids"][0].upper()]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "catalog.json"
            path.write_text(json.dumps(modified))
            with self.assertRaisesRegex(ManifestError, "duplicate toolkit package identity"):
                load_catalog(path)

    def test_duplicate_package_cannot_remain_port_required(self):
        rows = [{"id": name, "path": name + ".deb", "type": "TWEAK", "issues": [],
                 "dependencies": [], "sha256": ("a" if name == "first" else "b") * 64,
                 "package": {"Package": "ellekit", "Architecture": "iphoneos-arm64"}}
                for name in ("first", "second")]
        catalog = {"ellekit": {"upstream_project": "https://example.invalid/ellekit"}}
        plan = conversion_plan(rows, resolve_graph(rows), catalog)
        self.assertTrue(all(item["status"] == "UNKNOWN" for item in plan))
        self.assertTrue(all(item["repo_admission"] == "BLOCKED" for item in plan))

    def test_identical_package_copies_resolve_to_one_canonical_artifact(self):
        rows = [{"id": name, "path": name + ".deb", "type": "TWEAK", "issues": [],
                 "dependencies": [], "sha256": "a" * 64,
                 "package": {"Package": "ellekit", "Version": "1",
                             "Architecture": "iphoneos-arm64"}}
                for name in ("first", "second")]
        consumer = {"id": "consumer", "path": "consumer.deb", "type": "TWEAK",
                    "issues": [], "dependencies": ["ellekit"], "sha256": "c" * 64,
                    "package": {"Package": "consumer", "Version": "1",
                                "Architecture": "iphoneos-arm64"}}
        graph = resolve_graph(rows + [consumer])
        self.assertEqual(graph["duplicate_packages"], {})
        self.assertEqual(graph["identical_copies"]["ellekit"],
                         {"canonical": "first", "copies": ["second"]})
        self.assertEqual(graph["edges"][0]["to"], "first")
        catalog = {"ellekit": {"upstream_project": "https://example.invalid/ellekit",
                                  "trust_state": "OFFICIAL"}}
        plan = {item["id"]: item for item in conversion_plan(rows + [consumer], graph, catalog)}
        self.assertNotIn("DUPLICATE_ARTIFACT_COPY", plan["first"]["blockers"])
        self.assertIn("DUPLICATE_ARTIFACT_COPY", plan["second"]["blockers"])

    def test_hash_pinned_candidate_resolves_conflicting_builds(self):
        rows = [{"id": name, "path": name + ".deb", "type": "TWEAK", "issues": [],
                 "dependencies": [], "sha256": ("a" if name == "first" else "b") * 64,
                 "package": {"Package": "ellekit", "Version": name,
                             "Architecture": "iphoneos-arm64"}}
                for name in ("first", "second")]
        consumer = {"id": "consumer", "path": "consumer.deb", "type": "TWEAK",
                    "issues": [], "dependencies": ["ellekit"], "sha256": "c" * 64,
                    "package": {"Package": "consumer", "Version": "1",
                                "Architecture": "iphoneos-arm64"}}
        pin = {"ellekit": {"component_id": "second", "artifact_sha256": "b" * 64}}
        graph = resolve_graph(rows + [consumer], pin)
        self.assertEqual(graph["edges"][0]["to"], "second")
        self.assertEqual(graph["selected_candidates"]["ellekit"]["rejected"], ["first"])
        self.assertEqual(graph["duplicate_packages"], {})
        plan = {item["id"]: item for item in conversion_plan(rows + [consumer], graph, {})}
        self.assertIn("SUPERSEDED_CANDIDATE", plan["first"]["blockers"])
        self.assertNotIn("SUPERSEDED_CANDIDATE", plan["second"]["blockers"])
        stale = resolve_graph(rows + [consumer],
                              {"ellekit": {"component_id": "second", "artifact_sha256": "d" * 64}})
        self.assertIn("ellekit", stale["duplicate_packages"])
        self.assertIn("CANDIDATE_PIN_MISMATCH:ellekit", stale["candidate_pin_errors"])

    def test_candidate_registry_rejects_unpinned_path_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            registry = root / "compat/ios27/reviewed-candidates.json"
            registry.parent.mkdir(parents=True)
            registry.write_text(json.dumps({"schema": 1, "candidates": {
                "ellekit": {"component_id": "../../escape", "artifact_sha256": "a" * 64}}}))
            pins, errors = load_candidate_pins(root)
            self.assertEqual(pins, {})
            self.assertEqual(errors, ["CANDIDATE_PIN_INVALID"])
            registry.unlink()
            registry.symlink_to(root / "outside.json")
            self.assertEqual(load_candidate_pins(root)[1], ["CANDIDATE_REGISTRY_INVALID"])

    def test_doodle_port_manifest_stays_blocked(self):
        path = Path(__file__).resolve().parents[2] / "compat/ios27/doodle/0sky-compat.json"
        manifest = validate_compat_manifest(json.loads(path.read_text()))
        self.assertEqual(manifest["status"], "OSKY_PORTED")
        self.assertEqual(manifest["repo_admission"], "BLOCKED")
        self.assertEqual(manifest["tests"]["license_provenance"], "BLOCKED")
        self.assertEqual(manifest["tests"]["uat"], "UNVERIFIED")
        self.assertFalse(manifest["probe_hooks_enabled_ios27"])

    def test_doodle_catalog_blocks_ios27_runtime(self):
        row = next(item for item in load_catalog()["components"] if item["id"] == "doodle")
        result = compatibility_for(row, ios_version="27.0", architecture="arm64e",
                                   root_model="rootless")
        self.assertEqual(result["result"], "ADAPTATION_REQUIRED")
        self.assertIn("16.7.8", result["reason"])

    def test_doodle_api_metadata_is_not_runtime_success(self):
        path = Path(__file__).resolve().parents[2] / "compat/ios27/doodle/api-map.json"
        mapping = json.loads(path.read_text())
        self.assertEqual(mapping["status"], "BLOCKED_MISSING_LEGACY_API")
        classes = mapping["classes"]
        self.assertEqual(classify_doodle_api(classes)["result"],
                         "API_SIGNATURES_PRESENT_UNVERIFIED_RUNTIME")
        broken = json.loads(json.dumps(classes))
        broken["SBLockScreenManager"]["methods"]["setPasscodeVisible:animated:"] = "v@:@"
        self.assertEqual(classify_doodle_api(broken)["result"], "BLOCKED")

    def test_missing_legacy_doodle_hook_stays_blocked(self):
        result = classify_hook_surface({})
        self.assertEqual(result["result"], "BLOCKED_MISSING_LEGACY_API")
        self.assertIn("BBServer", result["missing"])

    def test_admission_requires_runtime_smoke_uat_and_provenance(self):
        good = {name: {"result": "PASS", "artifact_sha256": "a" * 64,
                       "environment_hash": "b" * 64} for name in (
            "inventory", "dependency", "architecture", "pii_secrets", "build", "package",
            "installation", "registration", "runtime", "smoke", "uat", "license_provenance")}
        identity = {"artifact_sha256": "a" * 64, "environment_hash": "b" * 64}
        self.assertEqual(admission(good, "APP", **identity)["repo_admission"], "PASS")
        without_registration = {key: value for key, value in good.items() if key != "registration"}
        self.assertEqual(admission(without_registration, "TWEAK", **identity)["repo_admission"], "PASS")
        self.assertEqual(admission(good, "APP", artifact_sha256="c" * 64,
                                   environment_hash="b" * 64)["repo_admission"], "BLOCKED")
        del good["runtime"]
        self.assertEqual(admission(good, "APP", **identity)["repo_admission"], "BLOCKED")
        self.assertEqual(admission(good, "APP", quarantined=True, **identity)["repo_admission"], "QUARANTINED")

    def test_admission_requires_exact_maintainer_script_review(self):
        identity = {"artifact_sha256": "a" * 64, "environment_hash": "b" * 64}
        good = {name: {"result": "PASS", **identity} for name in REQUIRED_GATE}
        scripts = ["postinst:" + "c" * 64]
        result = admission(good, "APP", maintainer_scripts=scripts, **identity)
        self.assertEqual(result["repo_admission"], "BLOCKED")
        self.assertIn("maintainer_scripts", result["missing_or_failed"])
        good["maintainer_scripts"] = {"result": "PASS", **identity,
                                     "reviewed_scripts": ["postinst:" + "d" * 64]}
        self.assertEqual(admission(good, "APP", maintainer_scripts=scripts,
                                   **identity)["repo_admission"], "BLOCKED")
        good["maintainer_scripts"]["reviewed_scripts"] = scripts
        self.assertEqual(admission(good, "APP", maintainer_scripts=scripts,
                                   **identity)["repo_admission"], "PASS")

    def test_manifest_rejects_cosmetic_pass(self):
        manifest = {"schema": 1, "target": "ios27", "package": "example.tool",
                    "status": "PORT_REQUIRED", "repo_admission": "BLOCKED",
                    "tests": {name: "UNVERIFIED" for name in REQUIRED_GATE}}
        self.assertEqual(validate_compat_manifest(manifest)["status"], "PORT_REQUIRED")
        manifest["status"] = "PASS"
        manifest["repo_admission"] = "PASS"
        with self.assertRaisesRegex(ValueError, "PASS lacks"):
            validate_compat_manifest(manifest)

    def test_manifest_rejects_pass_without_maintainer_script_stage(self):
        manifest = {"schema": 1, "target": "ios27", "package": "example.tool",
                    "type": "TWEAK", "status": "PASS", "repo_admission": "PASS",
                    "original_sha256": "a" * 64, "resulting_artifact_sha256": "a" * 64,
                    "environment_hash": "b" * 64, "reviewed_receipt_sha256": "c" * 64,
                    "source_commit": "d" * 40, "license": "MIT",
                    "maintainer_scripts": [{"name": "postinst", "sha256": "e" * 64}],
                    "tests": {name: "PASS" for name in REQUIRED_GATE}}
        with self.assertRaisesRegex(ValueError, "PASS lacks"):
            validate_compat_manifest(manifest)
        manifest["tests"]["maintainer_scripts"] = "SKIP"
        with self.assertRaisesRegex(ValueError, "PASS lacks"):
            validate_compat_manifest(manifest)
        manifest["tests"]["maintainer_scripts"] = "PASS"
        self.assertEqual(validate_compat_manifest(manifest)["status"], "PASS")
        manifest["maintainer_scripts"][0]["sha256"] = "not-a-hash"
        with self.assertRaisesRegex(ValueError, "maintainer script manifest"):
            validate_compat_manifest(manifest)

    def test_report_repeatability(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "project"
            root.mkdir()
            (root / "helper.py").write_text("print('hello')\n")
            output = Path(directory) / "artifacts"
            first = write_reports(root, output)
            before = (output / "inventory.json").read_bytes()
            second = write_reports(root, output)
            self.assertEqual(first, second)
            self.assertEqual(before, (output / "inventory.json").read_bytes())
            self.assertEqual(len(scan(root)[0]), 1)

    def test_staged_artifacts_enter_inventory_on_repeated_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staged = root / "artifacts/compatibility/candidate.app"
            staged.mkdir(parents=True)
            (staged / "Info.plist").write_bytes(
                b'<?xml version="1.0"?><plist version="1.0"><dict>'
                b'<key>CFBundleIdentifier</key><string>test.candidate</string>'
                b'<key>CFBundleExecutable</key><string>candidate</string>'
                b'</dict></plist>')
            (staged / "candidate").write_bytes(
                struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0))
            output = root / "artifacts/compatibility/reports"
            first = write_reports(root, output)
            before = (output / "inventory.json").read_bytes()
            second = write_reports(root, output)
            self.assertEqual(first, second)
            self.assertEqual(before, (output / "inventory.json").read_bytes())
            rows = json.loads(before)["components"]
            self.assertTrue(any(row["path"] == "artifacts/compatibility/candidate.app"
                                and row["type"] == "APP" for row in rows))

    def test_symlinked_artifact_is_blocked_without_following_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root.parent / "external-artifact.app"
            staged = root / "artifacts/external.app"
            staged.parent.mkdir(parents=True)
            staged.symlink_to(outside, target_is_directory=True)
            rows, _ = scan(root)
            row = next(item for item in rows if item["path"] == "artifacts/external.app")
            self.assertEqual(row["type"], "APP")
            self.assertEqual(row["status"], "BLOCKED")
            self.assertEqual(row["issues"], ["SYMLINK_REQUIRES_REVIEW"])
            self.assertIsNone(row["sha256"])

    def test_packaged_app_identity_is_discovered_without_extraction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "artifacts/control.ipa"
            path.parent.mkdir()
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/Control.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "test.control", "CFBundleVersion": "2",
                    "CFBundleExecutable": "Control"}))
                archive.writestr("Payload/Control.app/Control",
                                 struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0))
            row = inspect_item(root, path)
            self.assertEqual(row["type"], "APP")
            self.assertEqual(row["bundle_id"], "test.control")
            self.assertEqual(row["status"], "UNVERIFIED")
            self.assertEqual(row["architectures"], ["arm64"])

    def test_tipa_uses_same_bounded_application_archive_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "research.tipa"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/Research.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "test.research", "CFBundleVersion": "1",
                    "CFBundleExecutable": "Research"}))
                archive.writestr("Payload/Research.app/Research",
                                 struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0))
            row = inspect_item(root, path)
            self.assertEqual(row["type"], "APP")
            self.assertEqual(row["bundle_id"], "test.research")
            self.assertEqual(row["architectures"], ["arm64"])
            rows, graph = scan(root)
            self.assertEqual(len(rows), 1)
            self.assertEqual(graph["build_order"], [row["id"]])

    def test_ipa_traversal_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "bad.ipa"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/Control.app/Info.plist", b"invalid")
                archive.writestr("Payload/../escape", b"unsafe")
            row = inspect_item(root, path)
            self.assertEqual(row["status"], "BLOCKED")
            self.assertIn("IPA_UNSAFE_PATH", row["issues"])

    def test_ipa_with_unsupported_architecture_is_blocked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "desktop.ipa"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/Desktop.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "test.desktop", "CFBundleVersion": "1",
                    "CFBundleExecutable": "Desktop"}))
                archive.writestr("Payload/Desktop.app/Desktop",
                                 struct.pack("<8I", 0xfeedfacf, 0x1000007, 0, 2, 0, 0, 0, 0))
            row = inspect_item(root, path)
            self.assertEqual(row["architectures"], ["x86_64"])
            self.assertIn("BLOCKED_BINARY_ONLY", row["issues"])

    def test_ipa_gets_admission_entry_and_compatibility_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "control.ipa"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("Payload/Control.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "test.Control", "CFBundleVersion": "1",
                    "CFBundleExecutable": "Control"}))
                archive.writestr("Payload/Control.app/Control",
                                 struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0))
            output = root / "artifacts/compatibility"
            summary = write_reports(root, output)
            self.assertEqual(summary["package_artifacts"], 1)
            admitted = json.loads((output / "repository-admission.json").read_text())["packages"]
            self.assertEqual(admitted[0]["repo_admission"], "BLOCKED")
            self.assertEqual(admitted[0]["package"], "test.Control")
            manifest = json.loads((output / "manifests" / stable_id("control.ipa") /
                                   "0sky-compat.json").read_text())
            self.assertEqual(manifest["package"], "test.control")
            self.assertEqual(manifest["architecture"], ["arm64"])
            path.unlink()
            self.assertEqual(write_reports(root, output)["package_artifacts"], 0)
            self.assertFalse((output / "manifests" / stable_id("control.ipa")).exists())
            self.assertEqual(json.loads((output / "manifest-index.json").read_text())
                             ["component_ids"], [])

    def test_only_exact_hash_pinned_device_evidence_can_admit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ipa = root / "zebra.ipa"
            with zipfile.ZipFile(ipa, "w") as archive:
                archive.writestr("Payload/Zebra.app/Info.plist", plistlib.dumps({
                    "CFBundleIdentifier": "xyz.willy.Zebra", "CFBundleVersion": "1",
                    "CFBundleExecutable": "Zebra"}))
                archive.writestr("Payload/Zebra.app/Zebra",
                                 struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 2, 0, 0, 0, 0))
            artifact_hash = hashlib.sha256(ipa.read_bytes()).hexdigest()
            environment_hash = "b" * 64
            receipt = {"schema": 1, "component_id": stable_id("zebra.ipa"),
                       "artifact_sha256": artifact_hash, "environment_hash": environment_hash,
                       "original_sha256": artifact_hash,
                       "resulting_artifact_sha256": artifact_hash, "quarantined": False,
                       "stages": {name: {"result": "PASS", "artifact_sha256": artifact_hash,
                                        "environment_hash": environment_hash}
                                  for name in REQUIRED_GATE}}
            evidence_dir = root / "compat/ios27/admission-evidence"
            evidence_dir.mkdir(parents=True)
            stage_dir = evidence_dir / artifact_hash
            stage_dir.mkdir()
            for name in REQUIRED_GATE:
                evidence_path = stage_dir / (name + ".json")
                evidence_path.write_text(json.dumps({
                    "schema": 1, "component_id": stable_id("zebra.ipa"),
                    "artifact_sha256": artifact_hash,
                    "environment_hash": environment_hash, "stage": name,
                    "result": "PASS", "observations": [{"expected": "verified",
                                                              "observed": "verified"}]}, sort_keys=True))
                receipt["stages"][name]["evidence_file"] = evidence_path.name
                receipt["stages"][name]["evidence_sha256"] = hashlib.sha256(
                    evidence_path.read_bytes()).hexdigest()
            receipt_path = evidence_dir / (artifact_hash + ".json")
            receipt_path.write_text(json.dumps(receipt, sort_keys=True))
            registry = evidence_dir.parent / "reviewed-admission.json"
            registry.write_text(json.dumps({"schema": 1, "receipts": {
                receipt_path.name: hashlib.sha256(receipt_path.read_bytes()).hexdigest()}}))
            catalog_path = root / "bridge/DeviceRuntime/zero_sky_core/research_toolkit_manifest.json"
            catalog_path.parent.mkdir(parents=True)
            catalog_path.write_bytes((Path(__file__).resolve().parents[2] /
                "bridge/DeviceRuntime/zero_sky_core/research_toolkit_manifest.json").read_bytes())
            output = root / "artifacts/compatibility"
            self.assertEqual(write_reports(root, output)["repo_admitted"], 1)
            manifest = json.loads((output / "manifests" / stable_id("zebra.ipa") /
                                   "0sky-compat.json").read_text())
            self.assertEqual(manifest["repo_admission"], "PASS")
            stage_evidence = stage_dir / "uat.json"
            stage_original = stage_evidence.read_bytes()
            stage_evidence.write_bytes(stage_original + b" ")
            self.assertEqual(write_reports(root, output)["repo_admitted"], 0)
            stage_evidence.write_bytes(stage_original)
            receipt_path.write_text(receipt_path.read_text() + " ")
            self.assertEqual(write_reports(root, output)["repo_admitted"], 0)
            admission_report = json.loads((output / "repository-admission.json").read_text())
            self.assertEqual(admission_report["packages"][0]["repo_admission"], "BLOCKED")
            self.assertIn("REVIEWED_ADMISSION_HASH_MISMATCH", admission_report["receipt_errors"][0])


if __name__ == "__main__":
    unittest.main()
