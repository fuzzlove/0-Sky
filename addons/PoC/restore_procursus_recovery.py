#!/usr/bin/env python3
"""Resume the verified Procursus bootstrap through one pinned recovery SSH route."""

import argparse
import asyncio
from pathlib import Path
import runpy
import sys

from repair_device_connection import HOST_TOOLS, profiles, usb_identity


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, worker = profiles(instance_name=args.instance_name)[args.udid]
    env = worker["EnvironmentVariables"]
    if env.get("CRYPSTORE_DEVICE_HOST") != "127.0.0.1":
        raise RuntimeError("Bootstrap requires the exact-device USB tunnel")
    sys.path.insert(0, str(HOST_TOOLS))
    import pair
    base = pair.ssh_base(
        "127.0.0.1", env["CRYPSTORE_DEVICE_PORT"], Path(env["CRYPSTORE_DEVICE_KEY"]),
        known_hosts=Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"]),
        host_alias=env["CRYPSTORE_DEVICE_HOST_ALIAS"],
    )
    if pair.ssh(base, "id -u").stdout.strip() != b"0":
        raise RuntimeError("Pinned SSH route did not prove root")
    kit = Path(__file__).resolve().parent / "srdsh-work/components/zero-sky/kit/srdssh"
    chain = runpy.run_path(str(kit / "bootstrap.py"), run_name="procursus_recovery")
    chain["verify_inputs"](kit, procursus=True)
    if chain["procursus_healthy"](base):
        print("Existing Procursus bootstrap is healthy; preserved.", flush=True)
        return 0
    count = chain["stream_procursus"](kit / "bootstrap_1900.tar.zst", base)
    if count < 1:
        raise RuntimeError("Verified Procursus archive had no installable entries")
    chain["configure_procursus"](base)
    if not chain["procursus_healthy"](base):
        raise RuntimeError("Procursus extraction completed but dpkg/apt health did not converge")
    print(f"Procursus bootstrap restored and verified ({count} entries).", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
