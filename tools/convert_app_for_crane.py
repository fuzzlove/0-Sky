#!/usr/bin/env python3
"""Create a deterministic private IPA with Crane's verified pre-main adapter."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime"))
sys.path.insert(0, str(ROOT / "tools"))

from deterministic_zip import build as build_zip
from zero_sky_compat.intake import extract_zip
from zero_sky_compat.macho_edit import add_load_dylib


REVIEWED_CRANE_SHA256 = "baae65e3d9122590a5c646aa8de5f8831eecb5f2b22bb1af69cb2b1356215328"
BOOTSTRAP_NAME = "@executable_path/Frameworks/0SkyCraneBootstrap.dylib"


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def run(arguments: list[str], *, timeout: int = 180) -> subprocess.CompletedProcess:
    completed = subprocess.run(arguments, stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=timeout, check=False)
    if completed.returncode:
        raise RuntimeError(Path(arguments[0]).name + " failed: " +
                           completed.stderr.decode("utf-8", "replace")[-800:])
    return completed


def entitlements(bundle: Path) -> bytes | None:
    completed = subprocess.run(
        ["codesign", "-d", "--entitlements", ":-", str(bundle)],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False)
    if not completed.stdout:
        return None
    try:
        value = plistlib.loads(completed.stdout)
    except plistlib.InvalidFileException as error:
        raise ValueError("application entitlements are malformed") from error
    if not isinstance(value, dict):
        raise ValueError("application entitlements are not a dictionary")
    return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)


def convert(source: Path, output: Path, *, crane: Path,
            bootstrap: Path, shim: Path) -> dict:
    source = source.resolve(strict=True)
    crane = crane.resolve(strict=True)
    bootstrap = bootstrap.resolve(strict=True)
    shim = shim.resolve(strict=True)
    output = output.resolve()
    report_path = output.with_suffix(output.suffix + ".0sky.json")
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    if report_path.exists() or report_path.is_symlink():
        raise FileExistsError(report_path)
    if digest(crane) != REVIEWED_CRANE_SHA256:
        raise ValueError("Crane dylib differs from the reviewed paid artifact")
    original_hash = digest(source)
    with tempfile.TemporaryDirectory(prefix="0sky-crane-convert-") as directory:
        root = Path(directory)
        extract_zip(source, root)
        applications = [path for path in (root / "Payload").glob("*.app")
                        if path.is_dir() and not path.is_symlink()]
        if len(applications) != 1:
            raise ValueError("IPA must contain exactly one top-level app")
        app = applications[0]
        info_path = app / "Info.plist"
        try:
            info = plistlib.loads(info_path.read_bytes())
        except (OSError, plistlib.InvalidFileException) as error:
            raise ValueError("application Info.plist is invalid") from error
        bundle = info.get("CFBundleIdentifier")
        executable_name = info.get("CFBundleExecutable")
        if (not isinstance(bundle, str) or not bundle or not isinstance(executable_name, str)
                or not executable_name or "/" in executable_name):
            raise ValueError("application identity is incomplete")
        executable = app / executable_name
        if executable.is_symlink() or not executable.is_file():
            raise ValueError("application executable is missing")
        preserved_entitlements = entitlements(app)

        frameworks = app / "Frameworks"
        frameworks.mkdir(mode=0o755, exist_ok=True)
        destinations = {
            "Crane.dylib": crane,
            "0SkyCraneBootstrap.dylib": bootstrap,
            "lib0SkySubstrateFunctionShim.dylib": shim,
        }
        for name, source_library in destinations.items():
            destination = frameworks / name
            if destination.exists() or destination.is_symlink():
                raise ValueError("application already contains reserved adapter path: " + name)
            shutil.copy2(source_library, destination)

        crane_copy = frameworks / "Crane.dylib"
        run(["install_name_tool", "-change",
             "@rpath/CydiaSubstrate.framework/CydiaSubstrate",
             "@rpath/lib0SkySubstrateFunctionShim.dylib", str(crane_copy)])
        run(["install_name_tool", "-rpath", "/var/jb/usr/lib", "@loader_path",
             str(crane_copy)])
        load_command = add_load_dylib(executable, BOOTSTRAP_NAME)

        marker = {
            "Schema": 1,
            "Adapter": "crane-pre-main-v1",
            "BundleIdentifier": bundle,
            "StateTransport": "private-data-handoff-v1",
            "Runtime": "embedded-reviewed-crane",
        }
        (app / "0SkyCraneAdapter.plist").write_bytes(
            plistlib.dumps(marker, fmt=plistlib.FMT_BINARY, sort_keys=True))
        for library in sorted(destinations):
            run(["codesign", "--force", "--sign", "-", "--timestamp=none",
                 str(frameworks / library)])
        sign = ["codesign", "--force", "--sign", "-", "--timestamp=none",
                "--identifier", bundle]
        if preserved_entitlements is not None:
            entitlement_path = root / "preserved-entitlements.plist"
            entitlement_path.write_bytes(preserved_entitlements)
            sign.extend(["--entitlements", str(entitlement_path)])
        sign.append(str(app))
        run(sign)
        run(["codesign", "--verify", "--deep", "--strict", str(app)])
        output.parent.mkdir(parents=True, exist_ok=True)
        build_zip(root, output)

    report = {
        "schema": 1,
        "adapter": "crane-pre-main-v1",
        "bundle_identifier": bundle,
        "source": source.name,
        "source_sha256": original_hash,
        "converted": output.name,
        "converted_sha256": digest(output),
        "reviewed_crane_sha256": REVIEWED_CRANE_SHA256,
        "load_command": load_command,
        "state_transport": "private-data-handoff-v1",
        "runtime_validation": "NOT_RUN",
        "compatibility": "ADAPTATION_REQUIRED",
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--crane-dylib", type=Path, required=True)
    parser.add_argument("--adapter-directory", type=Path,
                        default=ROOT / ".build/crane-app-adapter")
    args = parser.parse_args()
    report = convert(args.source, args.output, crane=args.crane_dylib,
                     bootstrap=args.adapter_directory / "0SkyCraneBootstrap.dylib",
                     shim=args.adapter_directory / "lib0SkySubstrateFunctionShim.dylib")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
