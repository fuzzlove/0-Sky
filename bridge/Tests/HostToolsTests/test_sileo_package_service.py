"""Sileo's root APT boundary accepts only typed, authenticated selections."""
from contextlib import nullcontext
import hashlib
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "DeviceRuntime"))
from zero_sky_core import sileo_package_service as service


class SileoPackageServiceTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(service, "isolated_apt_sources",
                                    side_effect=lambda **kwargs: nullcontext(
                                        ["-o", "Dir::Etc::sourcelist=/dev/null",
                                         "-o", "Dir::Etc::sourceparts=/reviewed-only"]))
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def package_runner(section="Utilities", dependencies="",
                       architecture="iphoneos-arm64", sha256=""):
        calls = []

        def run(arguments, **kwargs):
            calls.append(arguments)
            if arguments[0] == service.APT_CACHE:
                name, version = arguments[-1].split("=", 1)
                body = (f"Package: {name}\nVersion: {version}\n"
                        f"Architecture: {architecture}\nSection: {section}\n"
                        f"Depends: {dependencies}\n"
                        f"SHA256: {sha256}\n" if sha256 else
                        f"Package: {name}\nVersion: {version}\n"
                        f"Architecture: {architecture}\nSection: {section}\n"
                        f"Depends: {dependencies}\n").encode()
                return mock.Mock(returncode=0, stdout=body, stderr=b"")
            return mock.Mock(returncode=0, stdout=b"{}", stderr=b"")

        return run, calls

    def test_rejects_shell_options_paths_and_duplicates(self):
        bad = [
            {"id": "--allow-unauthenticated", "version": "1"},
            {"id": "../../etc/passwd", "version": "1"},
            {"id": "curl", "version": "1;id"},
            {"id": "curl-", "version": "1/2"},
        ]
        for package in bad:
            with self.subTest(package=package), self.assertRaises(service.SileoRequestError):
                service.validate_request({"operation": "install", "packages": [package]})
        with self.assertRaises(service.SileoRequestError):
            service.validate_request({"operation": "install", "packages":
                                      [{"id": "curl", "version": "8.7.1"}] * 2})
        self.assertEqual(service.validate_request({"operation": "remove", "packages":
                         [{"id": "com.example.tweak", "version": "1.0"}]}),
                         ("remove", ["com.example.tweak=1.0"]))
        with self.assertRaises(service.SileoRequestError):
            service.validate_request({"operation": "remove", "packages":
                [{"id": "one", "version": "1"}, {"id": "two", "version": "1"}]})

    def test_removal_requires_bridge_and_exact_single_package_plan(self):
        request = {"operation": "remove", "packages":
                   [{"id": "com.example.tweak", "version": "1.0"}]}
        with self.assertRaisesRegex(service.SileoRequestError, "paired Bridge"):
            service.execute(request, env={})
        def runner(arguments, **kwargs):
            return mock.Mock(returncode=0,
                stdout=b'{"Package":"com.example.tweak","Version":"1.0","Type":"Remv"}\n',
                stderr=b"")
        plan = service.execute(dict(request, operation="plan-remove"), env={}, run=runner)
        self.assertEqual(plan["result"], "PLAN_READY")
        def extra_runner(arguments, **kwargs):
            return mock.Mock(returncode=0,
                stdout=(b'{"Package":"com.example.tweak","Version":"1.0","Type":"Remv"}\n'
                        b'{"Package":"another","Version":"1.0","Type":"Remv"}\n'),
                stderr=b"")
        blocked = service.execute(dict(request, operation="plan-remove"),
                                  env={}, run=extra_runner)
        self.assertEqual(blocked["stage"], "DEPENDENCY_PLAN")

    def test_apt_uses_argument_array_and_keeps_signature_checks(self):
        runner, calls = self.package_runner()
        result = service.execute({"operation": "plan", "packages":
                                  [{"id": "curl", "version": "8.7.1"}]},
                                 env={"PATH": "/var/jb/usr/bin"}, run=runner)
        self.assertEqual(result["result"], "PLAN_READY")
        args = calls[-1]
        self.assertEqual(args[0], service.APT)
        self.assertEqual(args[-1], "curl=8.7.1")
        self.assertIn("--no-remove", args)
        self.assertIn("APT::Get::AllowUnauthenticated=false", args)
        self.assertIn("Dir::Etc::sourceparts=/reviewed-only", args)
        self.assertNotIn("--allow-downgrades", args)
        self.assertNotIn("--allow-remove-essential", args)
        self.assertEqual(len(calls), 1)

    def test_installed_is_not_ready(self):
        runner, _ = self.package_runner()
        result = service.execute({"operation": "install", "packages":
                                  [{"id": "curl", "version": "8.7.1"}]}, env={}, run=runner)
        self.assertEqual(result["result"], "INSTALL_REQUIRES_VERIFICATION")

    def test_unverified_tweak_plan_allows_download_then_install_requires_analysis(self):
        runner, calls = self.package_runner(section="Tweaks", dependencies="mobilesubstrate")
        request = {"packages": [{"id": "com.example.tweak", "version": "4.0.0"}]}
        plan = service.execute(dict(request, operation="plan"), env={}, run=runner)
        self.assertEqual(plan["result"], "PLAN_READY")
        self.assertEqual(calls[-1][0], service.APT)
        result = service.execute(dict(request, operation="install"), env={}, run=runner)
        self.assertEqual(result["stage"], "COMPATIBILITY_ANALYSIS")
        self.assertEqual(result["result"], "ANALYSIS_REQUIRED")
        self.assertEqual(result["compatibility_state"], "ADAPTATION_REQUIRED")
        self.assertIn("metadata was verified", result["stderr"])
        self.assertEqual(calls[-1][0], service.APT_CACHE)

    def test_legacy_arm_package_metadata_requires_analysis_not_architecture_block(self):
        runner, _ = self.package_runner(architecture="iphoneos-arm")
        result = service.execute({"operation": "plan", "packages":
                                  [{"id": "org.example.utility", "version": "1.0"}]},
                                 env={}, run=runner)
        self.assertEqual(result["result"], "PLAN_READY")

    def test_authorized_archive_name_is_install_only_and_typed(self):
        digest = "a" * 64
        self.assertEqual(service.validate_request({"operation": "install", "packages":
            [{"id": "com.example.app", "version": "1.0",
              "archive": digest + ".deb"}]}),
            ("install", ["com.example.app=1.0"]))
        for archive in ("../package.deb", "/tmp/package.deb", "a.deb", digest + ".zip"):
            with self.subTest(archive=archive), self.assertRaises(service.SileoRequestError):
                service.validate_request({"operation": "install", "packages":
                    [{"id": "com.example.app", "version": "1.0", "archive": archive}]})
        with self.assertRaises(service.SileoRequestError):
            service.validate_request({"operation": "plan", "packages":
                [{"id": "com.example.app", "version": "1.0",
                  "archive": digest + ".deb"}]})

    def test_authorized_archive_uses_signed_hash_and_local_staging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            container = root / "container"
            archive_dir = container / "Documents" / service.AUTHORIZED_ARCHIVE_DIRECTORY
            archive_dir.mkdir(parents=True, mode=0o700)
            data = b"reviewed deb fixture"
            digest = hashlib.sha256(data).hexdigest()
            source = archive_dir / (digest + ".deb")
            source.write_bytes(data)
            source.chmod(0o600)
            fields = {"package": "com.example.app", "version": "1.0",
                      "architecture": "iphoneos-arm", "sha256": digest,
                      "size": str(len(data))}
            control = (b"Package: com.example.app\nVersion: 1.0\n"
                       b"Architecture: iphoneos-arm\n")
            runner = mock.Mock(return_value=mock.Mock(
                returncode=0, stdout=control, stderr=b""))
            with (mock.patch.object(service, "_container", return_value=container),
                  mock.patch.object(service.os, "fchown")):
                staged = service._stage_authorized_archive(
                    source.name, fields, root, run=runner)
            self.assertEqual(staged.read_bytes(), data)
            self.assertEqual(staged.stat().st_mode & 0o777, 0o600)
            self.assertEqual(source.read_bytes(), data)
            staged.unlink()
            with mock.patch.object(service, "_container", return_value=container):
                with self.assertRaisesRegex(service.SileoRequestError, "metadata"):
                    service._stage_authorized_archive(
                        ("b" * 64) + ".deb", fields, root, run=runner)

    def test_install_uses_validated_authorized_archive(self):
        digest = "a" * 64
        runner, calls = self.package_runner(architecture="iphoneos-arm", sha256=digest)
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory) / "staged.deb"
            staged.write_bytes(b"fixture")
            with mock.patch.object(service, "_stage_authorized_archive",
                                   return_value=staged):
                result = service.execute({"operation": "install", "packages": [{
                    "id": "com.example.app", "version": "1.0",
                    "archive": digest + ".deb"}]}, env={}, cwd=directory, run=runner)
            self.assertEqual(result["result"], "INSTALL_REQUIRES_VERIFICATION")
            self.assertEqual(Path(calls[-1][-1]), staged)
            self.assertFalse(staged.exists())

    def test_refresh_cannot_request_packages_or_upgrade(self):
        self.assertEqual(service.validate_request({"operation": "refresh", "packages": []}),
                         ("refresh", []))
        with self.assertRaises(service.SileoRequestError):
            service.validate_request({"operation": "refresh", "packages":
                                      [{"id": "curl", "version": "8.7.1"}]})

    def test_credential_requires_root_owned_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "token"
            secret.write_text("a" * 64 + "\n")
            secret.chmod(0o600)
            if secret.stat().st_uid == 0:
                self.assertTrue(service.authenticated("a" * 64, secret))
                self.assertFalse(service.authenticated("b" * 64, secret))
            secret.chmod(0o644)
            self.assertFalse(service.authenticated("a" * 64, secret))

    def test_status_mirror_is_atomic_and_rejects_symbolic_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            container = root / "container"
            documents = container / "Documents"
            documents.mkdir(parents=True)
            status = root / "status"
            status.write_bytes(b"Package: example\nVersion: 1\n\n")
            original_fstat = service.os.fstat

            def root_owned(descriptor):
                info = original_fstat(descriptor)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=0,
                                       st_size=info.st_size)

            with (mock.patch.object(service, "_container", return_value=container),
                  mock.patch.object(service.os, "geteuid", return_value=0),
                  mock.patch.object(service.os, "fstat", side_effect=root_owned)):
                service.mirror_installed_status(data_root=root, status_path=status)
                destination = documents / "sileo-dpkg-status"
                self.assertEqual(destination.read_bytes(), status.read_bytes())
                self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
                self.assertFalse(list(documents.glob("*.tmp.*")))

                outside = root / "outside"
                outside.write_bytes(b"unchanged")
                destination.unlink()
                destination.symlink_to(outside)
                with self.assertRaisesRegex(service.SileoRequestError, "symbolic"):
                    service.mirror_installed_status(data_root=root, status_path=status)
                self.assertEqual(outside.read_bytes(), b"unchanged")

                destination.unlink()
                status.unlink()
                status.symlink_to(outside)
                with self.assertRaises(OSError):
                    service.mirror_installed_status(data_root=root, status_path=status)
                self.assertFalse(destination.exists())

    def test_status_mirror_requires_root(self):
        with mock.patch.object(service.os, "geteuid", return_value=501):
            with self.assertRaisesRegex(service.SileoRequestError, "root installer"):
                service.mirror_installed_status()

    def test_root_owned_container_record_avoids_directory_enumeration(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Application"
            root.mkdir()
            container = root / "11111111-2222-3333-4444-555555555555"
            container.mkdir()
            metadata = container / ".com.apple.mobile_container_manager.metadata.plist"
            metadata.write_bytes(__import__("plistlib").dumps(
                {"MCMMetadataIdentifier": service.BUNDLE_ID}))
            record = base / "0sky-sileo-container.json"
            container_info = container.stat()
            record.write_text(__import__("json").dumps({
                "schema": 2, "bundle_id": service.BUNDLE_ID,
                "path": str(container), "device": container_info.st_dev,
                "inode": container_info.st_ino, "uid": container_info.st_uid,
                "gid": container_info.st_gid}))
            record.chmod(0o600)
            original = service.DATA_ROOT
            original_lstat = Path.lstat

            def root_owned_record(path):
                info = original_lstat(path)
                if path == record:
                    return SimpleNamespace(st_mode=info.st_mode, st_uid=0,
                                           st_size=info.st_size)
                return info
            try:
                service.DATA_ROOT = root
                with (mock.patch.object(Path, "lstat", autospec=True,
                                        side_effect=root_owned_record),
                      mock.patch.object(service, "_discover_container",
                                        side_effect=AssertionError("must not enumerate"))):
                    self.assertEqual(service._container(root, record), container)
                    # Runtime validation is based on the root-owned binding,
                    # so an MCM metadata denial cannot break package staging.
                    metadata.write_bytes(__import__("plistlib").dumps(
                        {"MCMMetadataIdentifier": "com.example.wrong"}))
                    self.assertEqual(service._container(root, record), container)
                    altered = __import__("json").loads(record.read_text())
                    altered["inode"] += 1
                    record.write_text(__import__("json").dumps(altered))
                    with self.assertRaisesRegex(service.SileoRequestError, "identity changed"):
                        service._container(root, record)
                    altered["inode"] -= 1
                    record.write_text(__import__("json").dumps(altered))
                    record.chmod(0o644)
                    with self.assertRaisesRegex(service.SileoRequestError, "ownership"):
                        service._container(root, record)
            finally:
                service.DATA_ROOT = original

    def test_retired_container_record_is_rediscovered_and_rebound(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            root = base / "Application"
            root.mkdir()
            current = root / "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
            current.mkdir()
            record = base / "0sky-sileo-container.json"
            retired = root / "11111111-2222-3333-4444-555555555555"
            record.write_text(__import__("json").dumps({
                "schema": 2, "bundle_id": service.BUNDLE_ID,
                "path": str(retired), "device": 1, "inode": 2,
                "uid": 501, "gid": 501}))
            record.chmod(0o600)
            original_root = service.DATA_ROOT
            original_lstat = Path.lstat

            def root_owned_record(path):
                info = original_lstat(path)
                if path == record:
                    return SimpleNamespace(st_mode=info.st_mode, st_uid=0,
                                           st_size=info.st_size)
                return info
            try:
                service.DATA_ROOT = root
                with (mock.patch.object(Path, "lstat", autospec=True,
                                        side_effect=root_owned_record),
                      mock.patch.object(service.os, "geteuid", return_value=0),
                      mock.patch.object(service, "_discover_container",
                                        return_value=current) as discover,
                      mock.patch.object(service, "_record_container") as bind):
                    self.assertEqual(service._container(root, record), current)
                discover.assert_called_once_with(root)
                bind.assert_called_once_with(current, record)
            finally:
                service.DATA_ROOT = original_root

    def test_device_identity_is_bounded_and_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            documents = Path(directory)
            uid, gid = service.os.getuid(), service.os.getgid()
            identity = {"udid": "11111111-2222222222222222", "model": "iPhone13,2"}
            service._provision_device_identity(documents, uid, gid, identity)
            value = __import__("json").loads(
                (documents / service.APP_IDENTITY_NAME).read_text())
            self.assertEqual(value, {"schema": 1, **identity})
            self.assertEqual((documents / service.APP_IDENTITY_NAME).stat().st_mode & 0o777,
                             0o600)
            with self.assertRaisesRegex(service.SileoRequestError, "validated"):
                service._provision_device_identity(
                    documents, uid, gid, {"udid": "../bad", "model": "iPhone13,2"})


class ReviewedSourceTests(unittest.TestCase):
    def test_only_pinned_signed_sources_enter_apt_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources, keys, lists = (root / name for name in ("sources", "keys", "lists"))
            for path in (sources, keys / "trusted.gpg.d", lists):
                path.mkdir(parents=True)
            key = keys / "trusted.gpg.d/memo.gpg"
            key.write_bytes(b"reviewed-public-key")
            (sources / "procursus.sources").write_text(
                "Types: deb\nURIs: https://apt.procurs.us/\nSuites: 1900\n"
                "Components: main\n")
            (sources / "unknown.sources").write_text(
                "Types: deb\nURIs: https://unknown.example/\nSuites: ./\nTrusted: yes\n")
            (lists / "apt.procurs.us_dists_1900_InRelease").write_bytes(b"signed release")
            reviewed = [{"id": "procursus", "uri": "https://apt.procurs.us/",
                         "suite": "1900", "components": "main",
                         "architecture": "iphoneos-arm64",
                         "key_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
                         "signing_fingerprint": "ABCDEF", "trust_state": "OFFICIAL"}]
            signature = mock.Mock(returncode=0,
                                  stdout=b"[GNUPG:] VALIDSIG ABCDEF 2026\n", stderr=b"")
            with mock.patch.object(service, "_reviewed_manifest", return_value=reviewed):
                accepted = service.reviewed_sources(
                    source_root=sources, key_root=keys, list_root=lists,
                    run=mock.Mock(return_value=signature))
                self.assertEqual([item["id"] for item in accepted], ["procursus"])
                self.assertIn("Signed-By:", accepted[0]["stanza"])
                with service.isolated_apt_sources(
                        source_root=sources, key_root=keys, list_root=lists,
                        temporary_root=root,
                        run=mock.Mock(return_value=signature)) as options:
                    isolated = Path(options[-1].split("=", 1)[1])
                    self.assertEqual([path.name for path in isolated.iterdir()],
                                     ["procursus.sources"])
                self.assertFalse(isolated.exists())

    def test_changed_release_signature_blocks_package_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("sources", "keys/trusted.gpg.d", "lists"):
                (root / name).mkdir(parents=True)
            key = root / "keys/trusted.gpg.d/memo.gpg"
            key.write_bytes(b"reviewed-public-key")
            (root / "sources/procursus.sources").write_text(
                "Types: deb\nURIs: https://apt.procurs.us/\nSuites: 1900\n"
                "Components: main\n")
            (root / "lists/apt.procurs.us_dists_1900_InRelease").write_bytes(b"changed")
            reviewed = [{"id": "procursus", "uri": "https://apt.procurs.us/",
                         "suite": "1900", "components": "main",
                         "architecture": "iphoneos-arm64",
                         "key_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
                         "signing_fingerprint": "ABCDEF", "trust_state": "OFFICIAL"}]
            with mock.patch.object(service, "_reviewed_manifest", return_value=reviewed):
                with self.assertRaisesRegex(service.SileoRequestError, "unavailable"):
                    service.reviewed_sources(
                        source_root=root / "sources", key_root=root / "keys",
                        list_root=root / "lists",
                        run=mock.Mock(return_value=mock.Mock(returncode=1,
                                                             stdout=b"", stderr=b"bad sig")))


if __name__ == "__main__":
    unittest.main()
