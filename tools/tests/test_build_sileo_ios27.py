"""Supply-chain checks for the pinned Sileo inspection builder."""
from pathlib import Path
import plistlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import build_sileo_ios27 as builder


class SileoBuilderTests(unittest.TestCase):
    def test_reviewed_patches_match_pinned_hashes(self):
        patch_dir = Path(builder.__file__).resolve().parent / "patches"
        for name, digest in builder.PATCHES:
            with self.subTest(name=name):
                builder.verify_patch(patch_dir / name, digest)

    def test_tampered_patch_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            patch = Path(directory) / "modified.patch"
            patch.write_bytes(b"unreviewed bytes")
            with self.assertRaisesRegex(RuntimeError, "changed"):
                builder.verify_patch(patch, builder.PATCHES[0][1])

    def test_unreviewed_source_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(RuntimeError):
                builder.verify_checkout(Path(directory))

    def test_output_requires_explicit_unsigned_archive_name(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "unsigned inspection"):
                builder.build(None, Path(directory) / "Sileo.ipa")

    def test_candidate_requires_pinned_runtime_libraries(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "hash-pinned runtime libraries"):
                builder.build(None, Path(directory) / "Sileo.ipa", srd_candidate=True)

    def test_ios_bundle_drops_mac_privileged_helper_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            info = Path(directory) / "Info.plist"
            info.write_bytes(plistlib.dumps({"CFBundleIdentifier": builder.BUNDLE_ID,
                                             "SMPrivilegedExecutables": {"helper": "developer identity"}}))
            self.assertEqual(builder.remove_host_only_plist_keys(info),
                             ["SMPrivilegedExecutables"])
            self.assertEqual(plistlib.loads(info.read_bytes()),
                             {"CFBundleIdentifier": builder.BUNDLE_ID})
            self.assertEqual(builder.remove_host_only_plist_keys(info), [])

    def test_ios27_confirm_forwarder_requires_visible_second_tap(self):
        patch = (Path(builder.__file__).resolve().parent / "patches" /
                 "sileo-ios27-popup-touch.patch").read_text()
        self.assertIn("!confirm.isHidden", patch)
        self.assertIn("confirm.alpha > 0", patch)
        self.assertIn("confirm.window != nil", patch)
        self.assertIn("CACurrentMediaTime() + 0.75", patch)
        self.assertIn("window.hitTest(center, with: nil)", patch)
        self.assertIn("confirm.bounds.contains(point)", patch)
        self.assertNotIn("view.bounds.height > 800", patch)
        self.assertNotIn("0sky-confirm-touch-events.log", patch)

    def test_bridge_transaction_is_not_cancelled_by_popup_inactive_state(self):
        patch = (Path(builder.__file__).resolve().parent / "patches" /
                 "sileo-ios27-install-lifecycle.patch").read_text()
        self.assertIn("let bridgeTransaction", patch)
        self.assertIn("if !bridgeTransaction", patch)

    def test_havoc_identity_and_archive_handoff_are_reviewed(self):
        patch = (Path(builder.__file__).resolve().parent / "patches" /
                 "sileo-ios27-havoc.patch").read_text()
        self.assertIn("0sky-device-identity.json", patch)
        self.assertIn("identity.count == 3", patch)
        self.assertIn("0sky-authorized-packages", patch)
        self.assertIn("destination.hash(ofType: .sha256)", patch)
        self.assertIn("operatingSystemVersion.majorVersion < 27", patch)
        self.assertIn("unsolicited permission", patch)
        self.assertIn("secretStatus == errSecSuccess", patch)
        self.assertIn("tokenStatus == errSecSuccess", patch)
        self.assertIn("securely store the provider credentials", patch)
        self.assertIn("completion?(nil, true)", patch)
        self.assertIn("operatingSystemVersion.majorVersion < 27", patch)
        self.assertIn('value["archive"] = archive.lastPathComponent', patch)
        self.assertNotIn("allow-unauthenticated", patch)

    def test_ios27_confirm_downloads_before_bridge_install(self):
        patch = (Path(builder.__file__).resolve().parent / "patches" /
                 "sileo-ios27-confirm.patch").read_text()
        self.assertIn('setTitle("Downloading…"', patch)
        self.assertIn("manager.startMoreDownloads()", patch)
        self.assertIn("manager.reloadData(recheckPackages: false)", patch)
        self.assertIn("status == 193", patch)
        self.assertIn("Package downloaded and verified", patch)
        self.assertIn("Open 0-Sky Control → Compatibility", patch)
        self.assertNotIn("no in-app download is required", patch)

        queue_patch = (Path(builder.__file__).resolve().parent / "patches" /
                       "sileo-ios27-queue-state.patch").read_text()
        self.assertIn("manager.errors.isEmpty || bridgeQueue", queue_patch)

        transition_patch = (Path(builder.__file__).resolve().parent / "patches" /
                            "sileo-ios27-download-transition.patch").read_text()
        self.assertIn("awaitVerifiedBridgeInstall(remaining: 240)", transition_patch)
        self.assertIn("manager.verifyComplete()", transition_patch)
        self.assertIn("Package download verification timed out", transition_patch)

        recovery_patch = (Path(builder.__file__).resolve().parent / "patches" /
                          "sileo-ios27-cfnetwork-recovery.patch").read_text()
        self.assertIn("recoverVerifiedDownloads", recovery_patch)
        self.assertIn("values.fileSize == expectedSize", recovery_patch)
        self.assertIn("candidate.hash(ofType: .sha256) == expectedHash", recovery_patch)
        self.assertIn("stageVerifiedBridgeArchive", recovery_patch)
        self.assertIn("packageIDs: packages.compactMap", recovery_patch)

        diagnostic_patch = (Path(builder.__file__).resolve().parent / "patches" /
                            "sileo-ios27-download-diagnostic.patch").read_text()
        self.assertIn("verifiedDownloadDiagnostic", diagnostic_patch)
        self.assertIn("cache-files=", diagnostic_patch)

        directory_patch = (Path(builder.__file__).resolve().parent / "patches" /
                           "sileo-ios27-directory-validation.patch").read_text()
        self.assertIn("import Darwin", directory_patch)
        self.assertIn("lstat(directory.path, &directoryStat) == 0", directory_patch)
        self.assertIn("(directoryStat.st_mode & S_IFMT) == S_IFDIR", directory_patch)
        self.assertNotIn("+        let values = try directory.resourceValues", directory_patch)

        hash_key_patch = (Path(builder.__file__).resolve().parent / "patches" /
                          "sileo-ios27-hash-key.patch").read_text()
        self.assertEqual(hash_key_patch.count('+                guard let expectedHash = download.package.rawControl["sha256"]'), 1)
        self.assertEqual(hash_key_patch.count('+        guard let sha256 = package.rawControl["sha256"]'), 1)
        self.assertNotIn('+        guard let sha256 = package.rawControl["SHA256"]', hash_key_patch)

        status_ui_patch = (Path(builder.__file__).resolve().parent / "patches" /
                           "sileo-ios27-compatibility-status-ui.patch").read_text()
        self.assertIn('title: "Compatibility analysis required"', status_ui_patch)
        self.assertIn("self.hasErrored = status != 193", status_ui_patch)
        self.assertIn("self.presentCompatibilityAnalysisRequired()", status_ui_patch)

        archive_gate_patch = (Path(builder.__file__).resolve().parent / "patches" /
                              "sileo-ios27-verified-archive-gate.patch").read_text()
        self.assertIn("verifiedBridgeArchivesComplete", archive_gate_patch)
        self.assertIn("if manager.verifiedBridgeArchivesComplete(packageIDs: packageIDs)",
                      archive_gate_patch)
        self.assertIn("Verified package archive is missing; installation was not started.",
                      archive_gate_patch)
        self.assertIn("archive=", archive_gate_patch)
        self.assertNotIn("+        if recovered || manager.verifyComplete()", archive_gate_patch)

        archive_identity_patch = (Path(builder.__file__).resolve().parent / "patches" /
                                  "sileo-ios27-archive-identity.patch").read_text()
        self.assertIn("verifiedBridgeArchiveKey", archive_identity_patch)
        self.assertIn("download.package.version == version", archive_identity_patch)
        self.assertIn("guard requested.allSatisfy", archive_identity_patch)
        self.assertIn("if !removing && result.0 == 0", archive_identity_patch)
        self.assertIn("discardVerifiedBridgeArchives()", archive_identity_patch)

    def test_srd_auth_uses_upstream_keychain_scope(self):
        self.assertEqual(builder.UPSTREAM, "https://github.com/fuzzlove/Sileo.git")
        entitlements = plistlib.loads(builder.ENTITLEMENTS.read_bytes())
        self.assertEqual(entitlements.get("keychain-access-groups"),
                         ["org.coolstar.Sileo"])
        patch = (Path(builder.__file__).resolve().parent / "patches" /
                 "sileo-ios27-havoc.patch").read_text()
        self.assertNotIn("let accessGroup", patch)


if __name__ == "__main__":
    unittest.main()
