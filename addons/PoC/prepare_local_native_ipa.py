#!/usr/bin/env python3
"""Create a natively installable IPA from a finalized local SRD app bundle."""
from __future__ import annotations

import argparse
import pathlib
import plistlib
import shutil

from finish_native_install import prepare_signed_ipa, resign_bundle, resign_embedded_machos


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, type=pathlib.Path)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()

    source = args.app.resolve(strict=True)
    if source.is_symlink() or source.suffix != ".app":
        parser.error("--app must name a real application bundle")
    if any(path.is_symlink() for path in source.rglob("*")):
        parser.error("application bundle may not contain symbolic links")
    info = plistlib.loads((source / "Info.plist").read_bytes())
    if info.get("CFBundleIdentifier") != args.bundle_id:
        parser.error("application bundle identifier does not match --bundle-id")
    executable = info.get("CFBundleExecutable")
    if not isinstance(executable, str) or not (source / executable).is_file():
        parser.error("application executable is missing")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    payload = output / "Payload"
    payload.mkdir()
    app = payload / source.name
    shutil.copytree(source, app)

    # Establish a valid starting seal before prepare_signed_ipa adds the
    # appregistrard marker and performs the final bottom-up signing pass.
    resign_embedded_machos(app)
    nested = sorted((path for path in app.rglob("*")
                     if path.is_dir() and path.suffix.lower() in
                     (".app", ".appex", ".xpc", ".framework", ".bundle")),
                    key=lambda path: len(path.parts), reverse=True)
    for bundle in nested:
        metadata_path = bundle / "Info.plist"
        if not metadata_path.is_file():
            continue
        metadata = plistlib.loads(metadata_path.read_bytes())
        if not metadata.get("CFBundleExecutable"):
            continue
        identity = metadata.get("CFBundleIdentifier")
        if not isinstance(identity, str) or not identity:
            raise RuntimeError(f"Nested bundle identity is missing: {bundle}")
        resign_bundle(bundle, identity)
    resign_bundle(app, args.bundle_id)
    ipa = prepare_signed_ipa(app, args.bundle_id, output)
    print(ipa)


if __name__ == "__main__":
    main()
