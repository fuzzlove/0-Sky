#!/usr/bin/env python3
"""Launch Link on one exact connected SRD and capture its Start screen."""
import argparse
import asyncio
from pathlib import Path

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot

from repair_device_connection import profiles, usb_identity, worker_namespace

BUNDLE = "codes.liquidsky.research.zerosky"


async def capture(udid: str, destination: Path, instance_name: str | None = None) -> None:
    await usb_identity(udid)
    namespace = worker_namespace(profiles(instance_name=instance_name)[udid][1])
    namespace["ssh"]("/var/jb/usr/bin/killall ZeroSky", timeout=15, check=False)
    await asyncio.sleep(.4)
    opened = namespace["ssh"](
        "/var/jb/usr/bin/uiopen --bundleid " + BUNDLE, timeout=20, check=False
    )
    if opened.returncode:
        raise RuntimeError("Link launch failed")
    await asyncio.sleep(1.4)
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError("Exact-device mismatch")
        async with DvtProvider(rsd) as provider, Screenshot(provider) as screenshots:
            raw = await asyncio.wait_for(screenshots.get_screenshot(), timeout=15)
    destination.write_bytes(raw)
    print({"device": udid, "start_screen_image": str(destination)})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--instance-name")
    args = parser.parse_args()
    asyncio.run(capture(args.udid, args.output, args.instance_name))
