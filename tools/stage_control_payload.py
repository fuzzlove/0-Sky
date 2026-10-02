#!/usr/bin/env python3
"""Build, sign, and seal the canonical Control IPA in a prepared Link kit."""
from __future__ import annotations

import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile

try:
    from .deterministic_zip import build as build_zip
    from .stage_verified_kit import digest
except ImportError:
    from deterministic_zip import build as build_zip
    from stage_verified_kit import digest


ROOT = Path(__file__).resolve().parents[1]
# Package from Theos' finalized staging tree.  The object app predates the
# stage hooks that embed reviewed preference/runtime resources such as Crane.
APP = ROOT / "control/TrollStoreLite/.theos/_/var/jb/Applications/CrypStore.app"
APP_ENTITLEMENTS = ROOT / "control/TrollStoreLite/entitlements.plist"
HELPER_ENTITLEMENTS = ROOT / "control/RootHelper/entitlements.plist"
PAYLOAD_RELATIVE = "packages/Commissary-Universal.ipa"
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}


def _run(argv: list[str], timeout: int = 300) -> None:
    result = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"Control payload step failed: {Path(argv[0]).name} exit {result.returncode}")


def _validate_app(app: Path) -> dict:
    if app.is_symlink() or not app.is_dir() or app.name != "CrypStore.app":
        raise RuntimeError("canonical Control build output is absent or unsafe")
    if any(path.is_symlink() for path in app.rglob("*")):
        raise RuntimeError("canonical Control app contains a symbolic link")
    info = plistlib.loads((app / "Info.plist").read_bytes())
    if (info.get("CFBundleIdentifier") != "com.liquidsky.CrypStore" or
            info.get("CFBundleExecutable") != "CrypStore" or
            not (app / "CrypStore").is_file() or
            not (app / "trollstorehelper").is_file()):
        raise RuntimeError("canonical Control identity or helper is incomplete")
    return info


def _verify_entitlements(code: Path, declaration: Path) -> None:
    shown = subprocess.run(["/usr/bin/codesign", "--display", "--entitlements", ":-",
                            str(code)], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=30, check=False)
    if shown.returncode:
        raise RuntimeError("signed Control entitlement state cannot be read")
    try:
        effective = plistlib.loads(shown.stdout)
        required = plistlib.loads(declaration.read_bytes())
    except (ValueError, plistlib.InvalidFileException) as error:
        raise RuntimeError("signed Control entitlement state is invalid") from error
    if effective != required:
        raise RuntimeError("signed Control entitlements differ from the project declaration")


def _is_macho(path: Path) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        with path.open("rb") as stream:
            return stream.read(4) in MACHO_MAGICS
    except OSError:
        return False


def _sign_embedded_machos(app: Path) -> None:
    info = plistlib.loads((app / "Info.plist").read_bytes())
    main = app / info["CFBundleExecutable"]
    helper = app / "trollstorehelper"
    binaries = sorted((path for path in app.rglob("*")
                       if _is_macho(path) and path not in {main, helper}),
                      key=lambda path: len(path.parts), reverse=True)
    for binary in binaries:
        _run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
              "--generate-entitlement-der", "--preserve-metadata=entitlements",
              str(binary)])
        _run(["/usr/bin/codesign", "--verify", "--strict", str(binary)])


def stage(kit: Path, *, build: bool = True) -> dict:
    """Replace the kit's old Control IPA with this source tree's signed build."""
    if kit.is_symlink() or not kit.is_dir():
        raise RuntimeError("prepared kit directory is absent or unsafe")
    if build:
        theos = os.environ.get("THEOS")
        if not theos or not (Path(theos) / "makefiles/common.mk").is_file():
            raise RuntimeError("THEOS must identify a usable Theos checkout")
        _run(["make", "-C", str(ROOT / "control"), "control", f"THEOS={theos}"],
             timeout=1200)
    source_info = _validate_app(APP)
    manifest_path = kit / "SHA256SUMS"
    destination = kit / PAYLOAD_RELATIVE
    if (not manifest_path.is_file() or manifest_path.is_symlink() or
            not destination.is_file() or destination.is_symlink()):
        raise RuntimeError("prepared kit is missing its bound Control IPA slot")
    with tempfile.TemporaryDirectory(prefix="0sky-control-stage-", dir=kit.parent) as folder:
        work = Path(folder)
        archive_root = work / "archive"
        packaged = archive_root / "Payload/CrypStore.app"
        packaged.parent.mkdir(parents=True)
        shutil.copytree(APP, packaged)
        _validate_app(packaged)
        _sign_embedded_machos(packaged)
        _run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
              "--generate-entitlement-der", "--entitlements", str(HELPER_ENTITLEMENTS),
              str(packaged / "trollstorehelper")])
        _run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
              "--generate-entitlement-der", "--entitlements", str(APP_ENTITLEMENTS),
              str(packaged)])
        _run(["/usr/bin/codesign", "--verify", "--deep", "--strict", str(packaged)])
        _verify_entitlements(packaged / "trollstorehelper", HELPER_ENTITLEMENTS)
        _verify_entitlements(packaged, APP_ENTITLEMENTS)
        candidate = work / "control.ipa"
        build_zip(archive_root, candidate)
        # Import after the build so the manifest validates the exact finalized IPA.
        sys.path.insert(0, str(ROOT / "bridge/DeviceRuntime/zero_sky_core"))
        from control_payload import create_manifest, verify_manifest
        payload_manifest = create_manifest(candidate, APP_ENTITLEMENTS)
        verify_manifest(candidate, payload_manifest)
        if payload_manifest["identity"]["CFBundleVersion"] != source_info["CFBundleVersion"]:
            raise RuntimeError("packaged Control build number differs from source output")
        previous_manifest = manifest_path.read_bytes()
        rows = previous_manifest.decode("utf-8").splitlines()
        slots = {PAYLOAD_RELATIVE, "./" + PAYLOAD_RELATIVE}
        matches = [index for index, row in enumerate(rows)
                   if row.split(None, 1)[-1] in slots]
        if len(matches) != 1:
            raise RuntimeError("prepared kit lacks one unique Control IPA hash entry")
        new_hash = digest(candidate)
        slot = rows[matches[0]].split(None, 1)[-1]
        rows[matches[0]] = f"{new_hash}  {slot}"
        temporary_manifest = work / "SHA256SUMS"
        temporary_manifest.write_text("\n".join(sorted(rows)) + "\n", encoding="utf-8")
        previous_ipa = work / "previous.ipa"
        shutil.copy2(destination, previous_ipa)
        try:
            os.replace(candidate, destination)
            os.replace(temporary_manifest, manifest_path)
        except OSError:
            os.replace(previous_ipa, destination)
            manifest_path.write_bytes(previous_manifest)
            raise
    return {"bundle_id": payload_manifest["identity"]["CFBundleIdentifier"],
            "version": payload_manifest["identity"]["CFBundleShortVersionString"],
            "build": payload_manifest["identity"]["CFBundleVersion"],
            "sha256": new_hash}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kit", type=Path)
    parser.add_argument("--skip-build", action="store_true")
    arguments = parser.parse_args()
    print(json.dumps(stage(arguments.kit, build=not arguments.skip_build), sort_keys=True))
