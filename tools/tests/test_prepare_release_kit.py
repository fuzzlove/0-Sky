"""Versioned kit overrides remain manifest-valid and repeatable."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import prepare_release_kit as release
from tools.stage_verified_kit import digest
from tools.verify_prepared_kit import verify


class PrepareReleaseKitTests(unittest.TestCase):
    def test_overrides_are_manifest_bound_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source.py"
            source.write_text("print('portable')\n", encoding="utf-8")
            kit = root / "kit"
            target = kit / "host-mac/worker.py"
            target.parent.mkdir(parents=True)
            target.write_text("print('old')\n", encoding="utf-8")
            manifest = kit / "SHA256SUMS"
            retired = (
                "filza/install_cryptex_native.py",
                "automation/CrypStoreAutomation/crypstore_keeper.py",
                "automation/CrypStoreAutomation/sileo-package-bridge-v8.py",
                "automation/CrypStoreAutomation/sileo-research-bridge.py",
            )
            rows = [f"{digest(target)}  ./host-mac/worker.py"]
            for relative in retired:
                old = kit / relative
                old.parent.mkdir(parents=True, exist_ok=True)
                old.write_text("raise RuntimeError('legacy route')\n", encoding="utf-8")
                rows.append(f"{digest(old)}  ./{relative}")
            manifest.write_text("\n".join(rows) + "\n", encoding="utf-8")
            with patch.dict(release.OVERRIDES, {"host-mac/worker.py": source}, clear=True):
                release.apply_portability_overrides(kit)
                once = manifest.read_bytes()
                release.apply_portability_overrides(kit)
            self.assertEqual(manifest.read_bytes(), once)
            self.assertEqual(target.read_bytes(), source.read_bytes())
            self.assertIn(digest(target), manifest.read_text(encoding="utf-8"))
            self.assertIn("./PORTABILITY.json", manifest.read_text(encoding="utf-8"))
            catalog = kit / "automation/tools/srd-runtime-manager/zero_sky_core/research_toolkit_manifest.json"
            self.assertEqual(catalog.read_bytes(),
                             (release.ROOT / "bridge/DeviceRuntime/zero_sky_core/research_toolkit_manifest.json").read_bytes())
            self.assertIn(f"{digest(catalog)}  ./automation/tools/srd-runtime-manager/zero_sky_core/research_toolkit_manifest.json",
                          manifest.read_text(encoding="utf-8"))
            injector_license = kit / "automation/tools/srd-runtime-manager/sandboxed-injector/LICENSE"
            self.assertEqual(injector_license.read_bytes(),
                             release.RUNTIME_MANAGER_ADDITIONS[
                                 "automation/tools/srd-runtime-manager/sandboxed-injector/LICENSE"
                             ].read_bytes())
            self.assertIn(f"{digest(injector_license)}  ./automation/tools/srd-runtime-manager/sandboxed-injector/LICENSE",
                          manifest.read_text(encoding="utf-8"))

    def test_unprepared_kit_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            self.assertFalse(verify(Path(folder)))

    def test_link_embeds_only_manifest_verified_control(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "source"
            package = source / "packages/Commissary-Universal.ipa"
            package.parent.mkdir(parents=True)
            package.write_bytes(b"reviewed control payload")
            extra = source / "host-mac/legacy.txt"
            extra.parent.mkdir()
            extra.write_text("not a Link runtime asset")
            manifest = source / "SHA256SUMS"
            manifest.write_text(f"{digest(package)}  ./packages/Commissary-Universal.ipa\n"
                                f"{digest(extra)}  ./host-mac/legacy.txt\n")
            target = root / "link"
            release.stage_link_control_only(source, target)
            self.assertEqual((target / "packages/Commissary-Universal.ipa").read_bytes(),
                             package.read_bytes())
            self.assertFalse((target / "host-mac").exists())
            self.assertEqual(len((target / "SHA256SUMS").read_text().splitlines()), 1)
            package.write_bytes(b"tampered")
            with self.assertRaisesRegex(RuntimeError, "differs"):
                release.stage_link_control_only(source, root / "invalid")


if __name__ == "__main__":
    unittest.main()
