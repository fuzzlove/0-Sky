#!/usr/bin/env python3
"""Capture an exact SRD's current screen for post-boot UI verification."""
import argparse
import asyncio
from pathlib import Path

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot

from measure_bootsplash import visible_normal_ui
from repair_device_connection import usb_identity


async def capture(udid, destination):
    await usb_identity(udid)
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError("Exact device mismatch")
        async with DvtProvider(rsd) as provider, Screenshot(provider) as screenshots:
            raw = await asyncio.wait_for(screenshots.get_screenshot(), timeout=15)
    destination.write_bytes(raw)
    print({"device": udid, "normal_link_ui_visible": visible_normal_ui(raw),
           "image": str(destination)})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(capture(args.udid, args.output))
