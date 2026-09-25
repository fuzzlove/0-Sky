#!/usr/bin/env python3
"""Require exact source-controlled portability scripts in a prepared kit."""
from __future__ import annotations

import json
from pathlib import Path
import sys

try:
    from .prepare_release_kit import OVERRIDES
    from .stage_verified_kit import digest
except ImportError:
    from prepare_release_kit import OVERRIDES
    from stage_verified_kit import digest


def verify(kit: Path) -> bool:
    marker = kit / "PORTABILITY.json"
    try:
        if marker.is_symlink() or json.loads(marker.read_text(encoding="utf-8")) != {
            "schema": 1, "overrides": "source-controlled"}:
            return False
        for relative, source in OVERRIDES.items():
            target = kit / relative
            if target.is_symlink() or not target.is_file() or digest(target) != digest(source):
                return False
        return True
    except (OSError, ValueError):
        return False


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_prepared_kit.py KIT", file=sys.stderr)
        return 64
    if verify(Path(sys.argv[1])):
        print("PORTABLE_KIT=PASS")
        return 0
    print("PORTABLE_KIT=FAIL: run tools/prepare_release_kit.py", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
