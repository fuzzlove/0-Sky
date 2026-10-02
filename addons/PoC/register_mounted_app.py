#!/usr/bin/env python3
"""Register an app from an installed research cryptex via 0-Sky's paired SSH channel."""

import argparse
import os
import pathlib
import plistlib
import re
import runpy
import shlex
import subprocess
import sys


MOUNTS = "/private/var/run/com.apple.security.cryptexd/mnt"


class MissingMountError(RuntimeError):
    pass


def paired_ssh(udid: str):
    agents = pathlib.Path.home() / "Library/LaunchAgents"
    matches = []
    for path in agents.glob("com.liquidskysecurity.crypstore-worker.*.plist"):
        definition = plistlib.loads(path.read_bytes())
        environment = definition.get("EnvironmentVariables", {})
        if environment.get("CRYPSTORE_DEVICE_UDID") == udid:
            worker = next((pathlib.Path(arg) for arg in definition.get("ProgramArguments", [])
                           if arg.endswith("/crypstore_worker.py")), None)
            if worker and worker.is_file():
                matches.append((environment, worker))
    if len(matches) != 1:
        raise ValueError(f"Expected one configured 0-Sky worker for {udid}; found {len(matches)}")
    environment, worker = matches[0]
    os.environ.update(environment)
    namespace = runpy.run_path(str(worker), run_name="cryptex_registration_helper")
    return namespace["ssh"]


def active_mount(ssh, identifier: str) -> str:
    pattern = shlex.quote(identifier) + ".*"
    command = (
        f"for d in {MOUNTS}/{pattern}; do "
        'if [ -d "$d" ] && mount | grep -Fq " on $d ("; then echo "$d"; fi; '
        "done"
    )
    result = ssh(command, timeout=30)
    mounts = [line for line in result.stdout.decode().splitlines() if line]
    if not mounts:
        raise MissingMountError(f"No active mount for {identifier}")
    if len(mounts) != 1:
        raise RuntimeError(f"Expected one active mount for {identifier}; found {len(mounts)}")
    return mounts[0]


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
    parser.add_argument("--cryptex-id")
    parser.add_argument("--app-name", help="Directory name, such as ZeroSky.app")
    parser.add_argument("--inspect", action="store_true", help="Only report active mount and app path")
    parser.add_argument("--check-registrar", action="store_true",
                        help="Only verify the mounted appregistrard executable")
    options = parser.parse_args()
    if not options.inspect and not options.check_registrar:
        compatibility_stop("app-registration")
    if not options.check_registrar and not re.fullmatch(r"[A-Za-z0-9.-]+", options.cryptex_id or ""):
        parser.error("Invalid cryptex identifier")
    if not options.check_registrar and not re.fullmatch(r"[A-Za-z0-9._-]+\.app", options.app_name or ""):
        parser.error("Invalid app directory name")
    try:
        ssh = paired_ssh(options.udid)
        if options.check_registrar:
            registrar = active_mount(ssh, "codes.rambo.research.appregistrard") + "/usr/bin/appregistrard"
            if ssh(f"test -x {shlex.quote(registrar)}", timeout=15, check=False).returncode:
                raise MissingMountError("The mounted appregistrard executable is missing")
            print(f"Registration service ready: {registrar}", flush=True)
            return
        mount = active_mount(ssh, options.cryptex_id)
        candidates = [f"{mount}/System/Applications/{options.app_name}",
                      f"{mount}/Applications/{options.app_name}"]
        present = [candidate for candidate in candidates
                   if ssh(f"test -d {shlex.quote(candidate)}", timeout=15, check=False).returncode == 0]
        if len(present) != 1:
            raise RuntimeError(f"Expected one app directory in {mount}; found {len(present)}")
        app = present[0]
        print(f"Mounted app: {app}", flush=True)
        if options.inspect:
            return
        registrar = active_mount(ssh, "codes.rambo.research.appregistrard") + "/usr/bin/appregistrard"
        command = (f"{shlex.quote(registrar)} register --path "
                   f"{shlex.quote(app)} --absolute")
        result = ssh(command, timeout=180, check=False)
        sys.stdout.write(result.stdout.decode("utf-8", "replace"))
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
        if result.returncode:
            raise RuntimeError(f"appregistrard exited {result.returncode}")
    except subprocess.TimeoutExpired as error:
        parser.exit(3, f"error: Paired SSH command timed out after {error.timeout} seconds; "
                    "registrar availability could not be determined.\n")
    except MissingMountError as error:
        parser.exit(2 if options.check_registrar else 1, f"error: {error}\n")
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
