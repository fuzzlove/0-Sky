#!/usr/bin/env python3
"""Emit a deterministic, checksummed classification of repository files."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


OUTPUT = Path("manifests/repository-inventory.json")
TEST_PARTS = {"Tests", "tests"}
RUNTIME_PARTS = {"Resources", "Assets", "KitScripts"}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def classify(relative: Path) -> str:
    parts = set(relative.parts)
    text = relative.as_posix()
    if (text.startswith("addons/PoC/appsync-afc2d-srd-port/")
            or text.startswith("addons/PoC/srdsh-work/srdsh/vendor/")):
        return "required-source-or-maintenance-test"
    if text.startswith("addons/PoC/"):
        return "uncertain-retained-for-investigation"
    if parts & TEST_PARTS or relative.name.startswith("test_"):
        return "required-source-or-maintenance-test"
    if (parts & RUNTIME_PARTS or relative.suffix in {".plist", ".entitlements", ".icns"}
            or text.startswith("docs/assets/")):
        return "required-installation-or-runtime-asset"
    return "required-source-or-maintenance-test"


def inventory(root: Path) -> dict[str, object]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, capture_output=True, timeout=30, check=False,
    )
    if result.returncode:
        raise RuntimeError("git file inventory failed")
    paths = sorted({Path(value.decode("utf-8", "surrogateescape"))
                    for value in result.stdout.split(b"\0") if value})
    rows = []
    for relative in paths:
        if relative == OUTPUT:
            continue
        path = root / relative
        if path.is_symlink() or not path.is_file():
            kind = "uncertain-retained-for-investigation"
            digest, size = None, None
        else:
            kind = classify(relative)
            digest, size = sha256(path), path.stat().st_size
        rows.append({"path": relative.as_posix(), "category": kind,
                     "sha256": digest, "size": size})
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["category"]] = counts.get(row["category"], 0) + 1
    return {
        "schema": 1,
        "scope": "tracked and pending non-ignored repository files",
        "self_excluded": OUTPUT.as_posix(),
        "counts": dict(sorted(counts.items())),
        "excluded_reproducible_or_private_output": [
            ".build/", ".venv/", "artifacts/", "build/", "dist/", "DerivedData/",
            "installer-verification/", "logs/", "reports/", "research_sessions/",
            "addons/PoC/yoridan/",
        ],
        "files": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    payload = inventory(root)
    destination = args.output if args.output.is_absolute() else root / args.output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps(payload["counts"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
