#!/usr/bin/env python3
"""Build the reusable arm64/arm64e Crane pre-main and function-hook shims."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
SHIMS = ROOT / "bridge/DeviceRuntime/zero_sky_compat/shims"


def run(arguments: list[str]) -> None:
    subprocess.run(arguments, stdin=subprocess.DEVNULL, check=True,
                   capture_output=True, timeout=180)


def build(output: Path) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    sdk = subprocess.check_output(
        ["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    clang = subprocess.check_output(
        ["xcrun", "--sdk", "iphoneos", "--find", "clang"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="0sky-crane-adapter-") as directory:
        work = Path(directory)
        products: dict[str, list[Path]] = {
            "0SkyCraneBootstrap.dylib": [],
            "lib0SkySubstrateFunctionShim.dylib": [],
        }
        for architecture in ("arm64", "arm64e"):
            bootstrap = work / f"bootstrap-{architecture}.dylib"
            run([clang, "-fobjc-arc", "-dynamiclib", "-target",
                 f"{architecture}-apple-ios17.0", "-isysroot", sdk, "-Os",
                 "-framework", "Foundation", "-install_name",
                 "@rpath/0SkyCraneBootstrap.dylib",
                 str(SHIMS / "crane_pre_main.m"), "-o", str(bootstrap)])
            products["0SkyCraneBootstrap.dylib"].append(bootstrap)
            hook = work / f"substrate-{architecture}.dylib"
            run([clang, "-dynamiclib", "-target", f"{architecture}-apple-ios17.0",
                 "-isysroot", sdk, "-Os", "-install_name",
                 "@rpath/lib0SkySubstrateFunctionShim.dylib",
                 str(SHIMS / "substrate_function_interpose.c"), "-o", str(hook)])
            products["lib0SkySubstrateFunctionShim.dylib"].append(hook)
        report = {}
        for name, slices in products.items():
            destination = output / name
            run(["xcrun", "lipo", "-create", *(str(path) for path in slices),
                 "-output", str(destination)])
            run(["codesign", "--force", "--sign", "-", "--timestamp=none",
                 str(destination)])
            report[name] = hashlib.sha256(destination.read_bytes()).hexdigest()
        return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=ROOT / ".build/crane-app-adapter")
    args = parser.parse_args()
    for name, digest in build(args.output.resolve()).items():
        print(digest + "  " + name)


if __name__ == "__main__":
    main()
