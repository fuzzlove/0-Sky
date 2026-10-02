#!/usr/bin/env python3
"""Stage 1-5 iOS app packages for one research cryptex, or install prepared assets.

The prepare step does not create a signed cryptex. Use the SRD cryptex
tooling to produce a sealed image, trust cache, volume hash, and manifest.
"""

import argparse
import json
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

from device_python import select_device_python


def app_info(app: pathlib.Path) -> tuple[str, str]:
    if not app.is_dir() or app.suffix.lower() != ".app":
        raise ValueError(f"Expected an .app bundle: {app}")
    plist_path = app / "Info.plist"
    if not plist_path.is_file():
        raise ValueError(f"Missing Info.plist: {app}")
    info = plistlib.loads(plist_path.read_bytes())
    bundle_id = info.get("CFBundleIdentifier")
    executable = info.get("CFBundleExecutable")
    if not isinstance(bundle_id, str) or not bundle_id:
        raise ValueError(f"Missing CFBundleIdentifier: {app}")
    if not isinstance(executable, str) or not executable or not (app / executable).is_file():
        raise ValueError(f"Missing CFBundleExecutable or binary: {app}")
    return bundle_id, executable


def ipa_app(ipa: pathlib.Path, temporary: pathlib.Path) -> pathlib.Path:
    with zipfile.ZipFile(ipa) as archive:
        names = archive.namelist()
        for name in names:
            parts = pathlib.PurePosixPath(name).parts
            if name.startswith("/") or ".." in parts or "\\" in name:
                raise ValueError(f"Unsafe IPA archive member: {name}")
        apps = {parts[1] for name in names if (parts := pathlib.PurePosixPath(name).parts)
                and len(parts) >= 2 and parts[0] == "Payload" and parts[1].endswith(".app")}
        if len(apps) != 1:
            raise ValueError(f"Expected exactly one Payload/*.app in {ipa}; found {len(apps)}")
    # ditto preserves executable modes and symlinks from signed iOS app bundles.
    subprocess.run(["ditto", "-x", "-k", str(ipa), str(temporary)], check=True)
    return temporary / "Payload" / next(iter(apps))


def deb_apps(deb: pathlib.Path, temporary: pathlib.Path) -> list[pathlib.Path]:
    """Extract app-only Debian packages; maintainer scripts are never run."""
    tool = shutil.which("dpkg-deb")
    if not tool:
        raise ValueError("dpkg-deb is required for .deb inputs")
    subprocess.run([tool, "--extract", str(deb), str(temporary)], check=True)
    roots = [temporary / name for name in ("Applications", "System/Applications",
             "var/jb/Applications")]
    apps = [app for root in roots if root.is_dir()
            for app in root.iterdir() if app.suffix.lower() == ".app" and app.is_dir()]
    if not apps:
        raise ValueError(f"No Applications/*.app found in {deb}")
    if any(app.is_symlink() or not app.resolve().is_relative_to(temporary.resolve())
           for app in apps):
        raise ValueError(f"Unsafe app path in {deb}")
    # Other package files may depend on a writable root or maintainer scripts.
    # Refuse those packages instead of silently producing an incomplete cryptex.
    for entry in temporary.rglob("*"):
        if entry.is_dir() and not entry.is_symlink():
            continue
        if not any(entry == app or app in entry.parents for app in apps):
            raise ValueError(f"Unsupported non-app DEB payload: {entry.relative_to(temporary)}")
    return apps


def prepare(args: argparse.Namespace) -> None:
    if not 1 <= len(args.apps) <= 5:
        raise ValueError("Provide 1 to 5 .app, .ipa, or .deb paths")
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError(f"Output already exists: {output}")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", args.identifier) or "." not in args.identifier:
        raise ValueError("--identifier must be a reverse-DNS style identifier")
    if not re.fullmatch(r"[A-Za-z0-9.]+", args.version):
        raise ValueError("--version must use letters, numbers, and periods")
    for source in args.apps:
        if not source.exists() or source.suffix.lower() not in (".app", ".ipa", ".deb"):
            raise ValueError(f"Expected an existing .app, .ipa, or .deb: {source}")
    if args.template and not args.template.is_dir():
        raise ValueError(f"Template must be a directory: {args.template}")

    with tempfile.TemporaryDirectory(prefix="research-cryptex-") as tmp:
        scratch = pathlib.Path(tmp)
        stage = scratch / "dstroot"
        if args.template:
            shutil.copytree(args.template, stage, symlinks=True)
        else:
            stage.mkdir()
        destination = stage / "System" / "Applications"
        destination.mkdir(parents=True, exist_ok=True)
        records = []
        bundle_ids = set()
        names = set()
        for index, source in enumerate(args.apps):
            suffix = source.suffix.lower()
            if suffix == ".app":
                extracted = [source]
            elif suffix == ".ipa":
                extracted = [ipa_app(source, scratch / f"ipa-{index}")]
            else:
                extracted = deb_apps(source, scratch / f"deb-{index}")
            for app in extracted:
                bundle_id, executable = app_info(app)
                if bundle_id in bundle_ids or app.name.casefold() in names or (destination / app.name).exists():
                    raise ValueError(f"Duplicate app name or bundle ID: {app.name} ({bundle_id})")
                bundle_ids.add(bundle_id)
                names.add(app.name.casefold())
                shutil.copytree(app, destination / app.name, symlinks=True)
                records.append({"source": str(source.resolve()), "app": app.name,
                                "bundle_id": bundle_id, "executable": executable})
        if len(records) > 5:
            raise ValueError("A cryptex supports at most five staged apps")
        # The output is created only after all inputs pass validation.
        output.mkdir(parents=True)
        shutil.copytree(stage, output / "dstroot", symlinks=True)
        (output / "apps.json").write_text(json.dumps({"identifier": args.identifier,
            "version": args.version, "apps": records}, indent=2) + "\n")
    print(f"Staged {len(records)} app(s) in {output / 'dstroot' / 'System' / 'Applications'}")
    if args.dmg:
        dmg = output / "research-apps.dmg"
        subprocess.run(["hdiutil", "create", "-srcfolder", str(output / "dstroot"),
                        "-fs", "APFS", "-format", "UDRO", str(dmg)], check=True)
        print(f"Created source DMG: {dmg}")
    else:
        print("Staging complete; use make_cryptex.py to create the research cryptex.")


def install(args: argparse.Namespace) -> None:
    paths = (args.image, args.trust_cache, args.volume_hash, args.build_manifest)
    for path in paths:
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"Missing or empty cryptex asset: {path}")
    if args.image.suffix.lower() == ".ipa" or args.image.is_dir():
        raise ValueError("--image must be a prepared cryptex disk image, not an IPA or app")
    script = pathlib.Path(__file__).with_name("cryptex_native.py")
    command = [select_device_python(args.device_python), str(script), args.identifier, str(args.image),
               str(args.trust_cache), str(args.volume_hash), args.version,
               args.udid, str(args.build_manifest)]
    print(f"Installing {args.identifier} over RemoteXPC to {args.udid}", flush=True)
    subprocess.run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prep = sub.add_parser("prepare", help="Stage 1-5 apps into one cryptex filesystem")
    prep.add_argument("apps", nargs="+", type=pathlib.Path, help=".app, .ipa, or app-only .deb packages")
    prep.add_argument("--identifier", required=True, help="Research cryptex identifier")
    prep.add_argument("--version", required=True, help="Research cryptex version")
    prep.add_argument("--output", type=pathlib.Path, required=True, help="New output directory")
    prep.add_argument("--template", type=pathlib.Path, help="Optional app cryptex dstroot template")
    prep.add_argument("--dmg", action="store_true", help="Create an APFS source DMG with hdiutil")
    prep.set_defaults(func=prepare)
    load = sub.add_parser("install", help="Send prepared cryptex assets through cryptex_native.py")
    load.add_argument("--identifier", required=True)
    load.add_argument("--version", required=True)
    load.add_argument("--udid", required=True)
    load.add_argument("--image", required=True, type=pathlib.Path)
    load.add_argument("--trust-cache", required=True, type=pathlib.Path)
    load.add_argument("--volume-hash", required=True, type=pathlib.Path)
    load.add_argument("--build-manifest", required=True, type=pathlib.Path)
    load.add_argument("--device-python", help="Python with pinned pymobiledevice3 11.3.1")
    load.set_defaults(func=install)
    args = parser.parse_args()
    try:
        args.func(args)
    except (OSError, ValueError, subprocess.CalledProcessError, plistlib.InvalidFileException, zipfile.BadZipFile) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
