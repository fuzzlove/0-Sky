#!/usr/bin/env python3
"""Build one Cryptex1 bundle per .ipa, app-only .deb, or .app; optionally load on iOS."""

import argparse
import json
import pathlib
import re
import runpy
import shutil
import subprocess
import sys
import tempfile

from research_cryptex_poc import prepare


def cryptexctl_path(explicit: str | None) -> str:
    tool = explicit or shutil.which("cryptexctl")
    if not tool:
        fallback = pathlib.Path("/System/Library/SecurityResearch/usr/bin/cryptexctl")
        if fallback.is_file():
            tool = str(fallback)
    if not tool or not shutil.which(tool):
        raise ValueError("Apple Security Research cryptexctl is unavailable")
    return tool


def slug(name: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    if not result:
        raise ValueError(f"Cannot derive cryptex identifier from {name!r}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="+", type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path,
                        help="New directory for separate cryptex bundles")
    parser.add_argument("--identifier-prefix", default="org.example.research.packages")
    parser.add_argument("--version", default="1.0")
    parser.add_argument("--template", type=pathlib.Path,
                        help="Optional app cryptex filesystem template")
    parser.add_argument("--cryptexctl", help="Apple Security Research cryptexctl path")
    parser.add_argument("--device-python", help="Python with pinned pymobiledevice3 11.3.1")
    parser.add_argument("--sign-apps", action="store_true",
                        help="Sign staged app copies with the existing 0-Sky CrypStore worker")
    parser.add_argument("--udid", help="Paired iOS device UDID; loads each bundle over RemoteXPC")
    parser.add_argument("--skip-registration", action="store_true",
                        help="Only install cryptexes; do not verify or register app icons")
    parser.add_argument("--reboot-for-icons", action="store_true",
                        help="If icons are missing, reboot the device and wait for appregistrard")
    args = parser.parse_args()

    try:
        if args.skip_registration and args.reboot_for_icons:
            raise ValueError("--skip-registration and --reboot-for-icons cannot be combined")
        tool = cryptexctl_path(args.cryptexctl)
        required = {"ditto" if package.suffix.lower() == ".ipa" else "dpkg-deb"
                    for package in args.packages if package.suffix.lower() in (".ipa", ".deb")}
        if args.sign_apps:
            required.update({"ldid", "codesign", "otool", "xattr"})
        missing = sorted(name for name in required if not shutil.which(name))
        if missing:
            raise ValueError("Missing host tools: " + ", ".join(missing))
        if args.udid:
            from device_python import select_device_python
            selected_python = select_device_python(args.device_python)
            print(f"Device Python: {selected_python}", flush=True)
        signer = None
        if args.sign_apps:
            worker = pathlib.Path(__file__).resolve().parents[2] / (
                "bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py")
            if not worker.is_file():
                raise ValueError(f"Missing 0-Sky signing worker: {worker}")
            signer = runpy.run_path(str(worker), run_name="cryptex_poc_signing")["sign_app"]
        output = args.output.resolve()
        if output.exists():
            raise ValueError(f"Output already exists: {output}")
        if not re.fullmatch(r"[A-Za-z0-9.-]+", args.identifier_prefix) or "." not in args.identifier_prefix:
            raise ValueError("--identifier-prefix must be a reverse-DNS style identifier")
        script = pathlib.Path(__file__).with_name("make_cryptex.py")
        records = []
        with tempfile.TemporaryDirectory(prefix="package-cryptex-") as temp_name:
            temporary = pathlib.Path(temp_name)
            seen_ids: dict[str, str] = {}
            for index, source in enumerate(args.packages, 1):
                label = f"{index:02d}-{slug(source.stem)}"
                identifier = f"{args.identifier_prefix}.{slug(source.stem).replace('-', '')}{index}"
                staged = temporary / label
                prepare(argparse.Namespace(apps=[source], identifier=identifier,
                    version=args.version, output=staged, template=args.template, dmg=False))
                apps = json.loads((staged / "apps.json").read_text())["apps"]
                if signer:
                    for app in apps:
                        signer(staged / "dstroot/System/Applications" / app["app"],
                               staged / "signing")
                for app in apps:
                    previous = seen_ids.setdefault(app["bundle_id"], str(source))
                    if previous != str(source):
                        print(f"App ID collision: {app['bundle_id']} in {previous} and {source}",
                              file=sys.stderr, flush=True)
                records.append({"source": str(source.resolve()), "label": label,
                                "identifier": identifier, "apps": apps, "stage": staged,
                                "signing": "0-Sky sign_app" if signer else "preserved"})

            output.mkdir(parents=True)
            for record in records:
                target = output / record["label"]
                command = [sys.executable, str(script), "--dstroot",
                           str(record["stage"] / "dstroot"), "--identifier",
                           record["identifier"], "--version", args.version,
                           "--output", str(target), "--cryptexctl", tool,
                           "--format", "cryptex1"]
                print(f"Building {record['source']} as {record['identifier']}", flush=True)
                subprocess.run(command, check=True)
                assets = json.loads((target / "assets.json").read_text())
                record["bundle"] = assets["bundle"]
                del record["stage"]

        (output / "packages.json").write_text(json.dumps(records, indent=2) + "\n")
        print(f"Built {len(records)} Cryptex1 bundle(s) in {output}", flush=True)
        if not args.udid:
            return

        ids: dict[str, str] = {}
        conflicts = []
        for record in records:
            for app in record["apps"]:
                bundle_id = app["bundle_id"]
                if bundle_id in ids:
                    conflicts.append(bundle_id)
                ids[bundle_id] = record["source"]
        if conflicts:
            print("App registration may conflict for duplicate bundle IDs: "
                  + ", ".join(sorted(set(conflicts))), file=sys.stderr, flush=True)

        installer = pathlib.Path(__file__).with_name("install_built_cryptex.py")
        install_command = [sys.executable, str(installer), str(output),
                           "--udid", args.udid, "--cryptexctl", tool,
                           "--device-python", selected_python]
        if args.skip_registration:
            install_command.append("--skip-registration")
        if args.reboot_for_icons:
            install_command.append("--reboot-for-icons")
        subprocess.run(install_command, check=True)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
