from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import host_runtime_manifest as runtime  # noqa: E402


class HostRuntimeManifestTests(unittest.TestCase):
    def make_kit(self, root: Path) -> Path:
        license_path = root / "host-mac/runtime/LICENSE.txt"
        license_path.parent.mkdir(parents=True)
        license_path.write_text("test license\n", encoding="utf-8")
        components = []
        for name in sorted(runtime.REQUIRED):
            path = root / "host-mac/runtime/bin" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            path.chmod(0o755)
            components.append({
                "name": name,
                "path": path.relative_to(root).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "architectures": ["arm64", "x86_64"],
                "version": "test",
                "license": license_path.relative_to(root).as_posix(),
                "runtime_requirements": ["test fixture"],
                "destination": "application-bundled",
                "verification": "sha256+script",
            })
        manifest = root / "host-mac/HOST_RUNTIME_MANIFEST.json"
        manifest.write_text(json.dumps({"schema": 1, "platform": "macOS",
                                        "components": components}), encoding="utf-8")
        return manifest

    def test_complete_manifest_passes_schema_and_hash_validation(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.make_kit(root)
            result = runtime.verify(root, inspect_binaries=False)
            self.assertEqual(result["architectures"], ["arm64", "x86_64"])
            self.assertEqual(result["components"], len(runtime.REQUIRED))

    def test_missing_runtime_component_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = self.make_kit(root)
            value = json.loads(manifest.read_text())
            value["components"] = value["components"][1:]
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(runtime.RuntimeManifestError, "missing"):
                runtime.verify(root, inspect_binaries=False)

    def test_runtime_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = self.make_kit(root)
            value = json.loads(manifest.read_text())
            value["components"][0]["path"] = "../outside"
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaisesRegex(runtime.RuntimeManifestError, "unsafe"):
                runtime.verify(root, inspect_binaries=False)

    def test_architecture_payload_hash_is_verified(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = self.make_kit(root)
            value = json.loads(manifest.read_text())
            payloads = {}
            for architecture in ("arm64", "x86_64"):
                path = root / f"host-mac/runtime/python/{architecture}/python3"
                path.parent.mkdir(parents=True)
                path.write_bytes(architecture.encode())
                payloads[architecture] = {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            value["schema"] = 2
            value["components"][0]["payloads"] = payloads
            manifest.write_text(json.dumps(value), encoding="utf-8")
            runtime.verify(root, inspect_binaries=False)
            (root / payloads["arm64"]["path"]).write_bytes(b"changed")
            with self.assertRaisesRegex(runtime.RuntimeManifestError, "hash mismatch"):
                runtime.verify(root, inspect_binaries=False)


if __name__ == "__main__":
    unittest.main()
