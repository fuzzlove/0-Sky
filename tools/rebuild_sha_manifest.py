#!/usr/bin/env python3
"""Hash all kit files and confined symlinks in stable path order."""
from __future__ import annotations

import argparse
import os
from pathlib import Path

try:
    from .kit_manifest import digest
except ImportError:
    from kit_manifest import digest


def rebuild(root: Path) -> int:
    root = root.resolve(strict=True)
    rows = []
    for item in sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix()):
        relative = item.relative_to(root).as_posix()
        if relative == "SHA256SUMS" or item.is_dir() and not item.is_symlink():
            continue
        if not item.is_file():
            raise ValueError("kit contains unresolved symlink or unsupported entry")
        resolved = item.resolve(strict=True)
        if root not in resolved.parents:
            raise ValueError("kit symlink escapes root")
        if item.is_symlink():
            target = os.readlink(item)
            if Path(target).is_absolute() or ".." in Path(target).parts:
                raise ValueError("kit contains unsafe symlink")
        rows.append(f"{digest(item)}  ./{relative}")
    if not rows:
        raise ValueError("kit is empty")
    (root / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kit", type=Path)
    args = parser.parse_args()
    count = rebuild(args.kit)
    print(f"KIT_HASHES=PASS count={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
