#!/usr/bin/env python3
"""Verify immutable, distributable inputs recorded in manifest.json."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    manifest = json.loads((repo / "docs/reproducibility/manifest.json").read_text())
    failures: list[str] = []
    checked = 0
    for item in manifest["items"]:
        if not item.get("verify_in_checkout"):
            continue
        path = repo / item["path"]
        checked += 1
        if not path.is_file():
            failures.append(f"missing: {item['path']}")
        elif sha256(path) != item["sha256"]:
            failures.append(f"hash mismatch: {item['path']}")
    if failures:
        print("\n".join(failures))
        return 1
    print(f"MANIFEST=PASS checked={checked}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
