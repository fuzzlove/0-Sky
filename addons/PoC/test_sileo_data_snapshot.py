"""Focused checks for Sileo's device-local data preservation helper."""
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

import sileo_data_snapshot as snapshot


class SileoDataSnapshotTests(unittest.TestCase):
    def fixture(self, directory: Path) -> Path:
        root = directory / "Application"
        root.mkdir()
        container = root / "11111111-2222-3333-4444-555555555555"
        container.mkdir()
        (container / ".com.apple.mobile_container_manager.metadata.plist").write_bytes(
            plistlib.dumps({"MCMMetadataIdentifier": snapshot.BUNDLE_ID}))
        prefs = container / "Library" / "Preferences"
        prefs.mkdir(parents=True)
        (prefs / "settings.plist").write_bytes(b"user settings")
        docs = container / "Documents"
        docs.mkdir()
        (docs / "saved.txt").write_bytes(b"research notes")
        return container

    def test_snapshot_restores_and_verifies_user_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            container = self.fixture(root)
            with (mock.patch.object(snapshot, "DATA_ROOT", container.parent),
                  mock.patch.object(snapshot, "BACKUP_ROOT", root / "backups"),
                  mock.patch.object(snapshot.os, "chown")):
                result = snapshot.backup(container, "a" * 32)
                self.assertEqual(result["result"], "SNAPSHOT_VERIFIED")
                self.assertEqual(result["files"], 2)
                (container / "Documents" / "saved.txt").write_bytes(b"changed")
                restored = snapshot.restore(container, "a" * 32)
                self.assertEqual(restored["result"], "DATA_RESTORED_AND_VERIFIED")
                self.assertEqual((container / "Documents" / "saved.txt").read_bytes(),
                                 b"research notes")

    def test_symbolic_user_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            container = self.fixture(root)
            (container / "Documents" / "link").symlink_to(root / "elsewhere")
            with (mock.patch.object(snapshot, "DATA_ROOT", container.parent),
                  mock.patch.object(snapshot, "BACKUP_ROOT", root / "backups")):
                with self.assertRaisesRegex(RuntimeError, "UNSAFE"):
                    snapshot.backup(container, "b" * 32)

    def test_transient_webkit_hardlinks_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            container = self.fixture(root)
            cache = container / "Library/Caches/WebKit"
            cache.mkdir(parents=True)
            blob = cache / "blob"
            blob.write_bytes(b"transient")
            (cache / "other").hardlink_to(blob)
            with (mock.patch.object(snapshot, "DATA_ROOT", container.parent),
                  mock.patch.object(snapshot, "BACKUP_ROOT", root / "backups"),
                  mock.patch.object(snapshot.os, "chown")):
                result = snapshot.backup(container, "c" * 32)
                self.assertEqual(result["files"], 2)
                self.assertFalse((root / "backups" / ("c" * 32) /
                                  "payload/Library/Caches").exists())
                self.assertEqual(snapshot.restore(container, "c" * 32)["result"],
                                 "DATA_RESTORED_AND_VERIFIED")

    def test_os_owned_splashboard_snapshots_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            container = self.fixture(root)
            splash = container / "Library/SplashBoard/Snapshots/scene"
            splash.mkdir(parents=True)
            (splash / "snapshot.ktx").write_bytes(b"disposable")
            with (mock.patch.object(snapshot, "DATA_ROOT", container.parent),
                  mock.patch.object(snapshot, "BACKUP_ROOT", root / "backups"),
                  mock.patch.object(snapshot.os, "chown")):
                result = snapshot.backup(container, "d" * 32)
                self.assertEqual(result["files"], 2)
                self.assertFalse((root / "backups" / ("d" * 32) /
                                  "payload/Library/SplashBoard").exists())
                self.assertEqual(snapshot.restore(container, "d" * 32)["result"],
                                 "DATA_RESTORED_AND_VERIFIED")

    def test_backup_retains_only_three_newest_verified_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            container = self.fixture(root)
            with (mock.patch.object(snapshot, "DATA_ROOT", container.parent),
                  mock.patch.object(snapshot, "BACKUP_ROOT", root / "backups"),
                  mock.patch.object(snapshot.os, "chown")):
                tokens = [(hex(value)[2:] * 32)[:32] for value in range(10, 14)]
                for token in tokens:
                    result = snapshot.backup(container, token)
                self.assertEqual(result["pruned_snapshots"], [tokens[0]])
                self.assertEqual(sorted(path.name for path in (root / "backups").iterdir()),
                                 sorted(tokens[1:]))

    def test_retention_preserves_unknown_entries_and_rejects_unsafe_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backups = root / "backups"
            backups.mkdir()
            (backups / "operator-notes").write_text("keep")
            unsafe = backups / ("e" * 32)
            unsafe.mkdir()
            (unsafe / "manifest.json").write_text('{"bundle_id":"somebody.else","files":{}}')
            with mock.patch.object(snapshot, "BACKUP_ROOT", backups):
                with self.assertRaisesRegex(RuntimeError, "OWNER_MISMATCH"):
                    snapshot.prune_snapshots()
            self.assertTrue((backups / "operator-notes").exists())
            self.assertTrue(unsafe.exists())


if __name__ == "__main__":
    unittest.main()
