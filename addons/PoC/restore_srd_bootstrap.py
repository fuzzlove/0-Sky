#!/usr/bin/env python3
"""Restore the bundled SRD SSH/Procursus prerequisites using an existing 0-Sky profile."""

import argparse
import json
import pathlib
import plistlib
import runpy
import subprocess

from device_python import select_device_python


DEFAULT_SRDSH_KIT = (pathlib.Path(__file__).resolve().parent / "srdsh-work" /
                     "components/zero-sky/kit/srdssh")


def validate_srdsh_kit(kit: pathlib.Path, *, ssh_only: bool = True) -> pathlib.Path:
    """Validate the bundled checksum manifest without connecting to the device."""
    kit = kit.expanduser().resolve()
    bootstrap = kit / "bootstrap.py"
    if not bootstrap.is_file():
        raise ValueError(f"The SRD SSH bootstrap is missing: {bootstrap}")
    namespace = runpy.run_path(str(bootstrap), run_name="poc_srdsh_validation")
    namespace["verify_inputs"](kit, procursus=not ssh_only)
    return kit


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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--kit", default=DEFAULT_SRDSH_KIT, type=pathlib.Path,
                        help="SRDKit/srdssh directory (default: bundled srdsh-work kit)")
    parser.add_argument("--check", action="store_true", help="Device read-only authorization check")
    parser.add_argument("--ssh-only", action="store_true", help="Set up SSH without the Procursus bootstrap")
    parser.add_argument("--device-python", help="Pinned device Python interpreter")
    args = parser.parse_args()
    if not args.check:
        compatibility_stop("bootstrap-install")
    try:
        matches = []
        agents = pathlib.Path.home() / "Library/LaunchAgents"
        for path in agents.glob("com.liquidskysecurity.crypstore-worker.*.plist"):
            definition = plistlib.loads(path.read_bytes())
            environment = definition.get("EnvironmentVariables", {})
            if environment.get("CRYPSTORE_DEVICE_UDID") != args.udid:
                continue
            worker = next((pathlib.Path(value) for value in definition.get("ProgramArguments", [])
                           if value.endswith("/crypstore_worker.py")), None)
            if worker and worker.is_file():
                matches.append(worker.parents[2])
        if len(matches) != 1:
            raise ValueError(f"Expected one existing 0-Sky profile; found {len(matches)}")
        instance = matches[0]
        config = json.loads((instance / "config.json").read_text())
        if config.get("udid") != args.udid:
            raise ValueError("The selected profile targets a different device")
        kit = validate_srdsh_kit(args.kit, ssh_only=args.ssh_only)
        identity = pathlib.Path(config["ssh_key"]).expanduser()
        if not identity.is_file():
            raise ValueError("The existing profile's SSH identity is missing")
        command = [select_device_python(args.device_python), str(kit / "bootstrap.py"),
                   "--kit", str(kit), "--udid", args.udid,
                   "--identity", config["ssh_key"], "--port", str(config["ssh_port"]),
                   "--state", str(instance), "--no-reboot"]
        if args.ssh_only:
            command.append("--ssh-only")
        if args.check:
            command.append("--check")
        subprocess.run(command, check=True, timeout=1200)
    except (OSError, ValueError, RuntimeError, KeyError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
