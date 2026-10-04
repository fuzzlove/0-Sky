#!/usr/bin/env python3
"""Validate the self-contained macOS runtime shipped in an approved kit."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


REQUIRED = {"python3", "dpkg", "dpkg-deb", "iproxy", "idevice_id", "zstd", "ldid"}
ARCHITECTURES = {"arm64", "x86_64"}


class RuntimeManifestError(RuntimeError):
    pass


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def _confined(root: Path, relative: str) -> Path:
    value = Path(relative)
    if value.is_absolute() or ".." in value.parts or not value.parts:
        raise RuntimeManifestError(f"unsafe runtime path: {relative}")
    path = root / value
    if path.is_symlink() or not path.is_file() or root.resolve() not in path.resolve().parents:
        raise RuntimeManifestError(f"missing or unsafe runtime file: {relative}")
    return path


def verify(root: Path, *, inspect_binaries: bool = True) -> dict[str, object]:
    manifest = root / "host-mac/HOST_RUNTIME_MANIFEST.json"
    if manifest.is_symlink() or not manifest.is_file():
        raise RuntimeManifestError("missing host-mac/HOST_RUNTIME_MANIFEST.json")
    try:
        value = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeManifestError("invalid host runtime manifest") from error
    if value.get("schema") != 1 or value.get("platform") != "macOS":
        raise RuntimeManifestError("unsupported host runtime manifest schema or platform")
    components = value.get("components")
    if not isinstance(components, list):
        raise RuntimeManifestError("host runtime components must be a list")
    seen: set[str] = set()
    for component in components:
        if not isinstance(component, dict):
            raise RuntimeManifestError("invalid host runtime component")
        name = component.get("name")
        if not isinstance(name, str) or name in seen:
            raise RuntimeManifestError("duplicate or invalid host runtime component name")
        seen.add(name)
        path = _confined(root, str(component.get("path", "")))
        license_path = _confined(root, str(component.get("license", "")))
        expected = component.get("sha256")
        architectures = set(component.get("architectures", []))
        if (not re.fullmatch(r"[0-9a-f]{64}", str(expected))
                or digest(path) != expected or architectures != ARCHITECTURES
                or not isinstance(component.get("version"), str)
                or not component["version"]
                or not isinstance(component.get("runtime_requirements"), list)
                or component.get("destination") != "application-bundled"
                or component.get("verification") not in {"sha256+lipo", "sha256+script"}
                or not license_path.is_file()):
            raise RuntimeManifestError(f"invalid host runtime component: {name}")
        if not path.stat().st_mode & 0o111:
            raise RuntimeManifestError(f"host runtime component is not executable: {name}")
        if inspect_binaries and component["verification"] == "sha256+lipo":
            result = subprocess.run(
                ["/usr/bin/lipo", "-archs", str(path)], capture_output=True,
                text=True, timeout=10, check=False,
            )
            if result.returncode or set(result.stdout.split()) != ARCHITECTURES:
                raise RuntimeManifestError(f"host runtime component is not Universal 2: {name}")
    missing = REQUIRED - seen
    if missing:
        raise RuntimeManifestError("missing host runtime components: " + ", ".join(sorted(missing)))
    return {"schema": 1, "components": len(components), "architectures": sorted(ARCHITECTURES)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kit", type=Path)
    args = parser.parse_args()
    try:
        result = verify(args.kit.resolve(strict=True))
    except (OSError, RuntimeManifestError, subprocess.SubprocessError) as error:
        print(f"HOST_RUNTIME=FAIL {error}")
        return 2
    print("HOST_RUNTIME=PASS " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
