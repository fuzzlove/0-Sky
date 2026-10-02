#!/usr/bin/env python3
"""Load previously built Cryptex1 or research cryptex bundles onto iOS."""

import argparse
import json
import pathlib
import plistlib
import subprocess
import sys
import time

from device_python import select_device_python
from load_packages_as_cryptex import cryptexctl_path
from make_cryptex import inspect_bundle


def registered_ids(python: str, udid: str, bundle_ids: list[str]) -> set[str]:
    command = [python, "-m", "pymobiledevice3", "apps", "query",
               *bundle_ids, "--udid", udid]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    installed = json.loads(result.stdout)
    if not isinstance(installed, dict):
        raise ValueError("App registry query returned an unexpected result")
    return set(installed).intersection(bundle_ids)


def compatibility_stop(operation):
    import pathlib
    import sys
    for ancestor in pathlib.Path(__file__).resolve().parents:
        runtime = ancestor / "bridge" / "DeviceRuntime"
        if (runtime / "zero_sky_compat").is_dir():
            sys.path.insert(0, str(runtime))
            break
    from zero_sky_compat.integration import block_legacy_mutation
    block_legacy_mutation(operation)


def main() -> None:
    compatibility_stop('built-cryptex-install')

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("builds", nargs="+", type=pathlib.Path,
                        help="Package build directories or individual assets.json build directories")
    parser.add_argument("--udid", required=True, help="Paired iOS device UDID")
    parser.add_argument("--cryptexctl")
    parser.add_argument("--device-python", help="Python with pinned pymobiledevice3 11.3.1")
    parser.add_argument("--skip-registration", action="store_true",
                        help="Only install cryptexes; do not verify or register app icons")
    parser.add_argument("--reboot-for-icons", action="store_true",
                        help="If icons are missing, reboot the device and wait for appregistrard")
    args = parser.parse_args()
    try:
        if args.skip_registration and args.reboot_for_icons:
            raise ValueError("--skip-registration and --reboot-for-icons cannot be combined")
        records = []
        for build in args.builds:
            root = build.resolve()
            packages = root / "packages.json"
            if packages.is_file():
                entries = json.loads(packages.read_text())
            else:
                asset_file = root / "assets.json"
                if not asset_file.is_file():
                    raise ValueError(f"Expected packages.json or assets.json in {root}")
                entries = [json.loads(asset_file.read_text())]
            for record in entries:
                bundle = pathlib.Path(record["bundle"]).resolve()
                if not bundle.is_relative_to(root) or not bundle.is_dir():
                    raise ValueError(f"Missing bundle inside {root}: {bundle}")
                assets = inspect_bundle(bundle, "research")
                records.append((record["identifier"], bundle, assets, record.get("apps", [])))

        native_python = (select_device_python(args.device_python)
                         if any("Cryptex1,GenericDmg" in assets for _, _, assets, _ in records)
                         else None)
        for identifier, bundle, assets, _ in records:
            if "Cryptex1,GenericDmg" in assets:
                info = plistlib.loads(pathlib.Path(assets["Cryptex1,CryptexInfoPlist"]).read_bytes())
                command = [native_python,
                           str(pathlib.Path(__file__).with_name("research_cryptex_poc.py")),
                           "install", "--identifier", identifier,
                           "--version", info["CFBundleVersion"], "--udid", args.udid,
                           "--image", assets["Cryptex1,GenericDmg"],
                           "--trust-cache", assets["Cryptex1,GenericTrustCache"],
                           "--volume-hash", assets["Cryptex1,GenericVolume"],
                           "--build-manifest", assets["build_manifest"]]
                subprocess.run(command, check=True)
                continue

            tool = cryptexctl_path(args.cryptexctl)
            target = bundle.parent / "personalized"
            attempt = 2
            while target.exists():
                target = bundle.parent / f"personalized-{attempt}"
                attempt += 1
            target.mkdir()
            base = [tool, "--udid", args.udid]
            subprocess.run(base + ["personalize", "--variant", "research", "--persist",
                                   "--output-directory", str(target), str(bundle)], check=True)
            signed = list(target.glob("*.cxbd"))
            if len(signed) != 1:
                raise ValueError(f"Expected one personalized .cxbd in {target}; found {len(signed)}")
            subprocess.run(base + ["install", "--variant", "research", "--persist",
                                   str(signed[0])], check=True)
            print(f"Loaded {identifier} onto {args.udid}", flush=True)

        if not args.skip_registration:
            apps = {}
            for identifier, _, _, entries in records:
                for entry in entries:
                    bundle_id = entry["bundle_id"]
                    if bundle_id in apps:
                        print(f"Duplicate app ID {bundle_id}: only one registration is possible",
                              file=sys.stderr, flush=True)
                    else:
                        apps[bundle_id] = (identifier, entry["app"])
            if apps:
                python = native_python or select_device_python(args.device_python)
                bundle_ids = list(apps)
                present = registered_ids(python, args.udid, bundle_ids)
                if set(bundle_ids) - present and args.reboot_for_icons:
                    print("Rebooting for a fresh appregistrard mount scan; unlock the device once it returns",
                          flush=True)
                    subprocess.run([python, "-m", "pymobiledevice3", "diagnostics", "restart",
                                    "--udid", args.udid, "--reconnect"], check=True)
                    deadline = time.monotonic() + 240
                    while time.monotonic() < deadline:
                        try:
                            present = registered_ids(python, args.udid, bundle_ids)
                        except (subprocess.CalledProcessError, ValueError):
                            present = set()
                        if set(bundle_ids) <= present:
                            break
                        time.sleep(5)
                else:
                    helper = pathlib.Path(__file__).with_name("register_mounted_app.py")
                    for bundle_id in bundle_ids:
                        if bundle_id in present:
                            continue
                        identifier, app_name = apps[bundle_id]
                        print(f"Registering {bundle_id} from {identifier}", flush=True)
                        subprocess.run([sys.executable, str(helper), "--udid", args.udid,
                                        "--cryptex-id", identifier, "--app-name", app_name],
                                       check=True)
                    for attempt in range(6):
                        present = registered_ids(python, args.udid, bundle_ids)
                        if set(bundle_ids) <= present:
                            break
                        if attempt < 5:
                            time.sleep(2)
                missing = set(bundle_ids) - present
                if missing:
                    raise ValueError("Apps absent from the device registry: "
                                     + ", ".join(sorted(missing))
                                     + ". Unlock the device after reboot, or check appregistrard logs.")
                print("App registry contains: " + ", ".join(bundle_ids), flush=True)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
