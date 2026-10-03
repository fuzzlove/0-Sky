#!/usr/bin/env python3
import hashlib
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

EXPECTED = {
    "Package": "xyz.0sky.neoskybackground",
    "Version": "1.0.0+0sky27.6",
    "Architecture": "iphoneos-arm64",
}
ROOT = Path("var/jb")

def control(path: Path) -> dict[str, str]:
    text = subprocess.check_output(["dpkg-deb", "-f", str(path)], text=True)
    result = {}
    for line in text.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            result[key] = value
    return result

def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} package.deb")
    package = Path(sys.argv[1]).resolve()
    metadata = control(package)
    for key, value in EXPECTED.items():
        if metadata.get(key) != value:
            raise SystemExit(f"invalid {key}: {metadata.get(key)!r}")
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        subprocess.run(["dpkg-deb", "-x", str(package), str(root)], check=True)
        dylib = root / ROOT / "Library/MobileSubstrate/DynamicLibraries/NeoSkyBackground.dylib"
        prefs = root / ROOT / "Library/PreferenceBundles/NeoSkyBackgroundPreferences.bundle/NeoSkyBackgroundPreferences"
        entry = root / ROOT / "Library/PreferenceLoader/Preferences/NeoSkyBackgroundPreferences.plist"
        descriptor = root / ROOT / "Library/MobileSubstrate/DynamicLibraries/NeoSkyBackground.plist"
        resources = root / ROOT / "Library/PreferenceBundles/NeoSkyBackgroundPreferences.bundle/Resources/Root.plist"
        for item in (dylib, prefs, entry, descriptor, resources):
            if not item.is_file():
                raise SystemExit(f"missing package file: {item.relative_to(root)}")
        for binary in (dylib, prefs):
            architectures = subprocess.check_output(["lipo", "-archs", str(binary)], text=True).split()
            if set(architectures) != {"arm64", "arm64e"}:
                raise SystemExit(f"unexpected architectures for {binary.name}: {architectures}")
        strings = subprocess.check_output(["strings", str(dylib)], text=True, errors="replace")
        for required in ("24A5390f", "SBHomeScreenView", "CSProminentDisplayView", "active-lock-and-home"):
            if required not in strings:
                raise SystemExit(f"missing runtime guard marker: {required}")
        with resources.open("rb") as stream:
            specifiers = plistlib.load(stream)["items"]
        controls = sum(item.get("cell", "").startswith(("PSSwitch", "PSSlider", "PSSegment")) for item in specifiers)
        if controls < 9:
            raise SystemExit(f"expected at least 9 native controls, found {controls}")
        lock = next((item for item in specifiers if item.get("key") == "lockEnabled"), None)
        if not lock or lock.get("default") is not False or "Experimental" not in lock.get("label", ""):
            raise SystemExit("Lock Screen must remain explicitly experimental and default-off")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    print(f"PASS package={package.name} sha256={digest} native_controls={controls}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
