#!/usr/bin/env python3
"""Offline structural validation for the Jellyfish iOS 27 package."""

from __future__ import annotations

import hashlib
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile


EXPECTED = {
    "Package": "xyz.cypwn.jellyfish",
    "Version": "1.6.5+0sky27.3",
    "Architecture": "iphoneos-arm64",
}
ROOT = Path("var/jb")
TWEAK = ROOT / "Library/MobileSubstrate/DynamicLibraries/Jellyfish27.dylib"
FILTER = ROOT / "Library/MobileSubstrate/DynamicLibraries/Jellyfish27.plist"
PREF_BUNDLE = ROOT / "Library/PreferenceBundles/Jellyfish27Preferences.bundle"
PREF_EXEC = PREF_BUNDLE / "Jellyfish27Preferences"
PREF_INFO = PREF_BUNDLE / "Info.plist"
PREF_ROOT = PREF_BUNDLE / "Resources/Root.plist"
PREF_ENTRY = ROOT / "Library/PreferenceLoader/Preferences/Jellyfish27Preferences.plist"
HELPER = ROOT / "usr/bin/jellyfish27ctl"


def run(*args: str) -> str:
    return subprocess.run(
        args, check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ).stdout


def load_plist(path: Path) -> dict:
    with path.open("rb") as stream:
        value = plistlib.load(stream)
    if not isinstance(value, dict):
        raise SystemExit(f"plist root is not a dictionary: {path}")
    return value


def require_fat_macho(path: Path) -> None:
    if not path.is_file():
        raise SystemExit(f"missing Mach-O: {path}")
    description = run("file", str(path))
    if "arm64" not in description or "arm64e" not in description:
        raise SystemExit(f"required arm64 and arm64e slices missing: {description.strip()}")
    run("ldid", "-e", str(path))


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} PACKAGE.deb", file=sys.stderr)
        return 2
    package = Path(sys.argv[1]).resolve()
    if not package.is_file():
        raise SystemExit(f"package not found: {package}")
    for tool in ("dpkg-deb", "file", "xcrun", "ldid", "strings"):
        if shutil.which(tool) is None:
            raise SystemExit(f"required validation tool not found: {tool}")

    observed = {}
    for name in EXPECTED:
        value = run("dpkg-deb", "-f", str(package), name).strip()
        observed[name] = value.split(": ", 1)[-1]
    if observed != EXPECTED:
        raise SystemExit(f"package metadata mismatch: {observed!r}")

    with tempfile.TemporaryDirectory(prefix="jellyfish27-check-") as temp:
        root = Path(temp) / "root"
        run("dpkg-deb", "-x", str(package), str(root))
        tweak = root / TWEAK
        prefs = root / PREF_EXEC
        helper = root / HELPER
        for binary in (tweak, prefs, helper):
            require_fat_macho(binary)

        linked = run("xcrun", "otool", "-L", str(prefs))
        framework = "/System/Library/PrivateFrameworks/Preferences.framework/Preferences"
        if framework not in linked:
            raise SystemExit("native preference bundle lacks Preferences.framework")

        tweak_strings = run("strings", str(tweak))
        for required in ("24A5390f", "SBFLockScreenDateView", "layoutSubviews"):
            if required not in tweak_strings:
                raise SystemExit(f"exact-build runtime guard is missing {required!r}")

        filter_plist = load_plist(root / FILTER)
        if filter_plist.get("Filter", {}).get("Bundles") != ["com.apple.springboard"]:
            raise SystemExit("injection filter is not SpringBoard-only")

        info = load_plist(root / PREF_INFO)
        if info.get("NSPrincipalClass") != "Jellyfish27PreferencesRootListController":
            raise SystemExit("native preference bundle has the wrong principal class")

        entry = load_plist(root / PREF_ENTRY).get("entry", {})
        if entry.get("bundle") != "Jellyfish27Preferences" or entry.get("cell") != "PSLinkCell":
            raise SystemExit("PreferenceLoader entry does not open the native bundle")

        specifiers = load_plist(root / PREF_ROOT).get("items")
        if not isinstance(specifiers, list) or not specifiers:
            raise SystemExit("native iOS 27 preference descriptor has no rows")
        supported = {
            "PSGroupCell", "PSSwitchCell", "PSSegmentCell", "PSSliderCell",
            "PSEditTextCell",
        }
        editable = 0
        for item in specifiers:
            if not isinstance(item, dict) or item.get("cell") not in supported:
                raise SystemExit(f"unsupported native preference row: {item!r}")
            if item.get("cellClass"):
                raise SystemExit(f"row depends on a custom preference cell: {item!r}")
            if item.get("cell") == "PSGroupCell":
                continue
            editable += 1
            if item.get("defaults") != "xyz.royalapps.jellyfish" or not item.get("key"):
                raise SystemExit(f"preference row lacks scoped storage: {item!r}")
            if item.get("PostNotification") != "xyz.royalapps.jellyfish.changed":
                raise SystemExit(f"preference row lacks the scoped reload notification: {item!r}")
            if item.get("cell") == "PSSegmentCell":
                values = item.get("validValues")
                titles = item.get("validTitles")
                if not values or not titles or len(values) != len(titles):
                    raise SystemExit(f"invalid segmented preference row: {item!r}")
        if editable != 8:
            raise SystemExit(f"expected 8 editable native controls, found {editable}")

    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    print(f"PASS package={package.name} sha256={digest} native_controls=8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

