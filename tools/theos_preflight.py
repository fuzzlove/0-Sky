#!/usr/bin/env python3
"""Validate the locked Theos source-build input without modifying it."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "manifests/source-dependencies.json"


class TheosError(RuntimeError):
    pass


def command(argv: list[str]) -> str:
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                                text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TheosError(f"unable to execute {Path(argv[0]).name}") from error
    if result.returncode:
        raise TheosError(f"{Path(argv[0]).name} returned {result.returncode}")
    return result.stdout.rstrip()


def verify(theos: Path) -> dict[str, object]:
    theos = theos.resolve(strict=True)
    lock = json.loads(LOCK.read_text(encoding="utf-8"))["theos"]
    if not (theos / "makefiles/common.mk").is_file():
        raise TheosError("makefiles/common.mk is missing")
    head = command(["git", "-C", str(theos), "rev-parse", "HEAD"])
    if head != lock["commit"]:
        raise TheosError("Theos revision differs from manifests/source-dependencies.json")
    status = command(["git", "-C", str(theos), "status", "--porcelain", "--untracked-files=no"])
    if status:
        raise TheosError("Theos checkout has tracked modifications")
    observed: dict[str, str] = {}
    for row in command(["git", "-C", str(theos), "submodule", "status", "--recursive"]).splitlines():
        if not row or row[0] != " ":
            raise TheosError("Theos submodule is absent, modified, or conflicted")
        fields = row[1:].split()
        if len(fields) < 2:
            raise TheosError("invalid Theos submodule inventory")
        observed[fields[1]] = fields[0]
    if observed != lock["submodules"]:
        raise TheosError("Theos submodule revisions differ from the dependency lock")
    for tool in ("xcrun", "ldid", "pkg-config", "make"):
        if not shutil.which(tool):
            raise TheosError(f"required source-build tool is missing: {tool}")
    if command(["pkg-config", "--exists", "openssl"]):
        raise TheosError("pkg-config cannot resolve OpenSSL")
    prefix = os.environ.get("LIBARCHIVE_PREFIX", "")
    if not prefix and shutil.which("brew"):
        prefix = command(["brew", "--prefix", "libarchive"])
    if not prefix or not (Path(prefix) / "include/archive.h").is_file():
        raise TheosError("set LIBARCHIVE_PREFIX to a libarchive development prefix")
    sdk = command(["xcrun", "--sdk", "iphoneos", "--show-sdk-version"])
    return {"status": "PASS", "theos_commit": head,
            "submodules": len(observed), "iphoneos_sdk": sdk}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--theos", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.theos)
    except (OSError, ValueError, KeyError, TheosError) as error:
        print(f"THEOS_PREFLIGHT=FAIL {error}")
        return 2
    print("THEOS_PREFLIGHT=PASS " + json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
