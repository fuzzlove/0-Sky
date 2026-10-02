#!/usr/bin/env python3
"""Build a complete iOS cryptex bundle with Apple's cryptexctl.

The resulting .cxbd contains the prepared image, loadable trust cache,
volume hash asset, and BuildManifest.plist. Personalization and installation are
separate operations.
"""

import argparse
import hashlib
import json
import pathlib
import plistlib
import shutil
import subprocess
import tempfile
import zipfile

from research_cryptex_poc import prepare


def inspect_bundle(bundle: pathlib.Path, variant: str) -> dict[str, str]:
    restore = bundle / "Restore"
    manifest_path = restore / "BuildManifest.plist"
    manifest = plistlib.loads(manifest_path.read_bytes())
    if not isinstance(manifest, dict) or not manifest.get("BuildIdentities"):
        raise ValueError("cryptexctl produced an invalid BuildManifest.plist")
    identities = [item for item in manifest["BuildIdentities"]
                  if item.get("Info", {}).get("Variant") == variant]
    if len(identities) != 1:
        raise ValueError(f"Expected one {variant} build identity")
    entries = identities[0].get("Manifest", {})
    if not ({"CryptexDMG", "LoadableTrustCache", "Ap,CryptexInfoPlist"} <= entries.keys()
            or {"Cryptex1,GenericDmg", "Cryptex1,GenericTrustCache",
                "Cryptex1,GenericVolume", "Cryptex1,CryptexInfoPlist"} <= entries.keys()):
        raise ValueError("BuildManifest lacks a complete research cryptex asset set")
    paths = {"build_manifest": str(manifest_path.resolve())}
    for name, entry in entries.items():
        relative = entry.get("Info", {}).get("Path")
        if not isinstance(relative, str):
            raise ValueError(f"Missing path for {name}")
        path = (restore / relative).resolve()
        if not path.is_relative_to(restore.resolve()) or not path.is_file() or not path.stat().st_size:
            raise ValueError(f"Missing or unsafe cryptex asset: {relative}")
        digest = hashlib.sha384()
        with path.open("rb") as asset:
            for chunk in iter(lambda: asset.read(1024 * 1024), b""):
                digest.update(chunk)
        if digest.digest() != entry.get("Digest"):
            raise ValueError(f"Cryptex asset digest mismatch: {relative}")
        paths[name] = str(path)
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apps", nargs="*", type=pathlib.Path,
                        help="1-5 .app, .ipa, or app-only .deb packages")
    parser.add_argument("--dstroot", type=pathlib.Path,
                        help="Existing cryptex filesystem root, instead of app inputs")
    parser.add_argument("--template", type=pathlib.Path,
                        help="Optional app cryptex dstroot template")
    parser.add_argument("--identifier", required=True,
                        help="Research cryptex reverse-DNS identifier")
    parser.add_argument("--version", required=True, help="Cryptex version")
    parser.add_argument("--udid", help="Target SRD UDID for cryptexctl")
    parser.add_argument("--output", required=True, type=pathlib.Path,
                        help="New output directory")
    parser.add_argument("--cryptexctl",
                        help="Path to SRD cryptexctl executable")
    parser.add_argument("--format", choices=("research", "cryptex1"), default="research",
                        help="Asset format; cryptex1 is for cryptex_native.py")
    args = parser.parse_args()

    try:
        if bool(args.apps) == bool(args.dstroot):
            raise ValueError("Provide 1-5 apps or --dstroot, not both")
        if args.dstroot and (not args.dstroot.is_dir() or args.template):
            raise ValueError("--dstroot must be a directory and cannot use --template")
        if args.apps and not 1 <= len(args.apps) <= 5:
            raise ValueError("Provide 1-5 apps")
        tool = args.cryptexctl or shutil.which("cryptexctl")
        if not tool:
            system_tool = pathlib.Path("/System/Library/SecurityResearch/usr/bin/cryptexctl")
            if system_tool.is_file():
                tool = str(system_tool)
        if not tool or not shutil.which(tool):
            raise ValueError(f"SRD cryptexctl is unavailable: {args.cryptexctl or 'cryptexctl'}")
        output = args.output.resolve()
        if output.exists():
            raise FileExistsError(f"Output already exists: {output}")

        with tempfile.TemporaryDirectory(prefix="make-cryptex-") as temporary:
            temp = pathlib.Path(temporary)
            if args.dstroot:
                root = args.dstroot.resolve()
            else:
                staged = temp / "stage"
                prepare(argparse.Namespace(apps=args.apps, identifier=args.identifier,
                    version=args.version, output=staged, template=args.template,
                    dmg=False))
                root = staged / "dstroot"

            output.mkdir(parents=True)
            command = [tool]
            if args.udid:
                command += ["--udid", args.udid]
            format_option = "--research" if args.format == "research" else "--use-cryptex1-format"
            command += ["create", format_option, "--identifier", args.identifier,
                        "--version", args.version, "--variant", "research",
                        "--output-directory", str(output), str(root)]
            subprocess.run(command, check=True)

            bundles = list(output.glob("*.cxbd"))
            if len(bundles) != 1:
                raise ValueError(f"Expected one .cxbd bundle, found {len(bundles)} in {output}")
            paths = inspect_bundle(bundles[0], "research")
            (output / "assets.json").write_text(json.dumps({
                "identifier": args.identifier, "version": args.version,
                "bundle": str(bundles[0].resolve()), "assets": paths,
            }, indent=2) + "\n")
            print(f"Created {args.format} cryptex: {bundles[0]}")
            for name, path in paths.items():
                print(f"  {name}: {path}")
    except (OSError, ValueError, plistlib.InvalidFileException, zipfile.BadZipFile,
            subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
