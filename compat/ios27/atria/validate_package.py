#!/usr/bin/env python3
"""Offline structural validation for the rebuilt rootless Atria package."""

from __future__ import annotations

import hashlib
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile


EXPECTED = {
    "Package": "me.lau.atria",
    "Version": "1.4.1+0sky27.1",
    "Architecture": "iphoneos-arm64",
}
MACHOS = (
    "var/jb/Library/MobileSubstrate/DynamicLibraries/Atria.dylib",
    "var/jb/Library/PreferenceBundles/AtriaPrefs.bundle/AtriaPrefs",
)


def run(*args: str) -> str:
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).stdout


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} PACKAGE.deb", file=sys.stderr)
        return 2
    package = Path(sys.argv[1]).resolve()
    if not package.is_file():
        raise SystemExit(f"package not found: {package}")
    for tool in ("dpkg-deb", "file", "xcrun", "ldid"):
        if shutil.which(tool) is None:
            raise SystemExit(f"required validation tool not found: {tool}")

    observed = {}
    for name in EXPECTED:
        value = run("dpkg-deb", "-f", str(package), name).strip()
        observed[name] = value.split(": ", 1)[-1]
    if observed != EXPECTED:
        raise SystemExit(f"package metadata mismatch: {observed!r}")

    with tempfile.TemporaryDirectory(prefix="atria-check-") as temp:
        root = Path(temp) / "root"
        run("dpkg-deb", "-x", str(package), str(root))
        for relative in MACHOS:
            binary = root / relative
            if not binary.is_file():
                raise SystemExit(f"missing Mach-O: {relative}")
            description = run("file", str(binary))
            if "arm64" not in description or "arm64e" not in description:
                raise SystemExit(f"required slices missing: {description.strip()}")
            run("ldid", "-e", str(binary))

        filter_path = root / "var/jb/Library/MobileSubstrate/DynamicLibraries/Atria.plist"
        with filter_path.open("rb") as stream:
            filter_plist = plistlib.load(stream)
        if filter_plist.get("Filter", {}).get("Bundles") != ["com.apple.springboard"]:
            raise SystemExit("Atria injection filter is not SpringBoard-only")

        prefs = root / "var/jb/Library/PreferenceBundles/AtriaPrefs.bundle/AtriaPrefs"
        linked = run("xcrun", "otool", "-L", str(prefs))
        required = "/System/Library/PrivateFrameworks/Preferences.framework/Preferences"
        if required not in linked:
            raise SystemExit("preference bundle lacks Preferences framework dependency")

    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    print(f"PASS package={package.name} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
