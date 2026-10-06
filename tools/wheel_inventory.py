#!/usr/bin/env python3
"""Inventory pinned offline Python wheels and their declared dependency metadata."""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import tempfile
import zipfile


NAME = "WHEEL_INVENTORY.json"


def sha256(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def inspect(wheelhouse: Path) -> dict[str, object]:
    wheels = []
    for path in sorted(wheelhouse.glob("*.whl")):
        with zipfile.ZipFile(path) as archive:
            members = [name for name in archive.namelist()
                       if name.endswith(".dist-info/METADATA")]
            if len(members) != 1:
                raise ValueError("wheel has missing or duplicate METADATA")
            metadata = BytesParser().parsebytes(archive.read(members[0]))
            package = metadata.get("Name")
            version = metadata.get("Version")
            if not package or not version:
                raise ValueError("wheel lacks package identity")
            license_value = (metadata.get("License-Expression") or metadata.get("License")
                             or next((value.removeprefix("License :: ")
                                      for value in metadata.get_all("Classifier", [])
                                      if value.startswith("License :: ")), "UNDECLARED"))
            # email.policy compatibility differs between the system Python
            # bundled with Xcode and the pinned release Python, especially for
            # folded multiline License headers. Store a canonical textual
            # value so verification is reproducible across supported hosts.
            license_value = " ".join(str(license_value).split())
            wheels.append({
                "source_artifact": path.name,
                "package": package,
                "version": version,
                "platform_tag": path.stem.split("-")[-1],
                "sha256": sha256(path),
                "license_metadata": license_value[:250],
                "dependencies": [" ".join(str(item).split())
                                 for item in metadata.get_all("Requires-Dist", [])],
            })
    if not wheels:
        raise ValueError("offline wheelhouse is empty")
    return {"schema_version": 1, "wheels": wheels}


def write(kit: Path) -> int:
    wheelhouse = kit / "host-mac/wheelhouse"
    data = inspect(wheelhouse)
    destination = kit / NAME
    fd, temporary = tempfile.mkstemp(prefix=".wheel-inventory-", dir=kit)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return len(data["wheels"])


def verify(kit: Path) -> bool:
    try:
        observed = json.loads((kit / NAME).read_text(encoding="utf-8"))
        return observed == inspect(kit / "host-mac/wheelhouse")
    except (OSError, ValueError, zipfile.BadZipFile):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kit", type=Path)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        okay = verify(args.kit)
        print("WHEEL_INVENTORY=" + ("PASS" if okay else "FAIL"))
        return 0 if okay else 2
    count = write(args.kit)
    print(f"WHEEL_INVENTORY=PASS count={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
