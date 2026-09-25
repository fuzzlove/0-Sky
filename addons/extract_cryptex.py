#!/usr/bin/env python3
"""Extract a Cryptex DMG (or any .dmg) on any platform.

This script uses the third‑party ``dmgextractor`` package, which works on macOS,
Linux, and on iOS Python environments (e.g. Pythonista) provided the package
is installed via ``pip install dmgextractor``.

If ``dmgextractor`` is not available, the script falls back to using the
macOS ``hdiutil`` command when it is present. On pure iOS the fallback will not
run, so the pure‑Python path is the recommended approach.
"""
import argparse
import os
import sys
import subprocess
import shutil

def _extract_with_hdiutil(dmg_path, out_dir):
    """Fallback extraction using macOS ``hdiutil``.
    This requires the host to be macOS and ``hdiutil`` to be in $PATH.
    """
    # Create a temporary mount point
    mount_point = os.path.join(out_dir, "_mount")
    os.makedirs(mount_point, exist_ok=True)
    # Attach the image (read‑only, no browsing)
    attach_cmd = ["hdiutil", "attach", dmg_path, "-readonly", "-noverify", "-noautoopen", "-mountpoint", mount_point]
    proc = subprocess.run(attach_cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"hdiutil attach failed: {proc.stderr.strip()}")
    # Copy everything out of the mount point
    for entry in os.listdir(mount_point):
        src = os.path.join(mount_point, entry)
        dst = os.path.join(out_dir, entry)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
    # Detach the image
    detach_cmd = ["hdiutil", "detach", mount_point]
    subprocess.run(detach_cmd, capture_output=True)
    # Clean up temporary mount point
    shutil.rmtree(mount_point, ignore_errors=True)
    return out_dir

def _extract_with_dmgextractor(dmg_path, out_dir):
    """Extraction using the ``dmgextractor`` Python package.
    The package provides a ``DMGExtractor`` class with an ``extract_all`` method.
    """
    try:
        from dmgextractor import DMGExtractor
    except ImportError as e:
        raise ImportError("dmgextractor not installed. Install via 'pip install dmgextractor' and retry.") from e
    os.makedirs(out_dir, exist_ok=True)
    extractor = DMGExtractor(dmg_path)
    extractor.extract_all(out_dir)
    return out_dir

def extract_dmg(dmg_path, out_dir=None):
    if not os.path.isfile(dmg_path):
        raise FileNotFoundError(f"{dmg_path} not found")
    out_dir = out_dir or os.path.splitext(dmg_path)[0] + "_extracted"
    # Try the pure‑Python extractor first – it works on iOS if the package is installed.
    try:
        return _extract_with_dmgextractor(dmg_path, out_dir)
    except Exception as exc:
        # If we are on macOS we can fall back to hdiutil.
        if sys.platform.startswith("darwin"):
            try:
                return _extract_with_hdiutil(dmg_path, out_dir)
            except Exception as e2:
                raise RuntimeError(f"Both extraction methods failed: {exc}; fallback error: {e2}")
        else:
            raise RuntimeError(f"Extraction failed and no macOS fallback is available: {exc}")

def main():
    parser = argparse.ArgumentParser(description="Extract a .dmg Cryptex for iOS or other platforms.")
    parser.add_argument("dmg", help="Path to the .dmg file to extract")
    parser.add_argument("-o", "--output", help="Destination folder (default: <dmg>_extracted)", default=None)
    args = parser.parse_args()
    try:
        out = extract_dmg(args.dmg, args.output)
        print(f"DMG extracted to: {out}")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
