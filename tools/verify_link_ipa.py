#!/usr/bin/env python3
"""Verify the bundled 0-Sky Link identity, icon assets, and code signature."""
from __future__ import annotations

import argparse
from pathlib import Path
import plistlib
import subprocess
import tempfile
import zipfile


BUNDLE = "codes.liquidsky.research.zerosky"


def verify(path: Path) -> None:
    if not path.is_file() or path.is_symlink():
        raise ValueError("Link IPA is missing or unsafe")
    with zipfile.ZipFile(path) as archive:
        names = set(archive.namelist())
        app = "Payload/ZeroSky.app/"
        info = plistlib.loads(archive.read(app + "Info.plist"))
        if (info.get("CFBundleIdentifier") != BUNDLE
                or info.get("CFBundleShortVersionString") != "1.9.0"
                or info.get("CFBundleVersion") != "45"
                or info.get("CFBundleExecutable") != "ZeroSky"):
            raise ValueError("Link IPA has the wrong app identity or version")
        icons = info.get("CFBundleIcons", {}).get("CFBundlePrimaryIcon", {}).get("CFBundleIconFiles", [])
        if (app + "ZeroSky" not in names or not isinstance(icons, list)
                or not any(app + name + "@2x.png" in names for name in icons)):
            raise ValueError("Link IPA executable or Home Screen icon is missing")
        if archive.testzip() is not None:
            raise ValueError("Link IPA has a damaged archive member")
    with tempfile.TemporaryDirectory(prefix="0sky-link-verify-") as temporary:
        extracted = Path(temporary) / "Payload/ZeroSky.app"
        unpack = subprocess.run(["/usr/bin/ditto", "-x", "-k", str(path), temporary],
                                capture_output=True, timeout=120, check=False)
        if unpack.returncode != 0:
            raise ValueError("Link IPA cannot be extracted")
        signed = subprocess.run(["/usr/bin/codesign", "--verify", "--deep", "--strict",
                                 str(extracted)], capture_output=True, timeout=60, check=False)
        if signed.returncode != 0:
            raise ValueError("Link IPA code signature is invalid")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    args = parser.parse_args()
    try:
        verify(args.ipa)
    except (OSError, ValueError, zipfile.BadZipFile, KeyError,
            plistlib.InvalidFileException, subprocess.TimeoutExpired) as error:
        print(f"LINK_IPA=FAIL CATEGORY={type(error).__name__}")
        return 2
    print("LINK_IPA=PASS IDENTITY=PASS ICON=PASS SIGNATURE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
