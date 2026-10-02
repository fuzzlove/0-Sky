#!/usr/bin/env python3
"""Capture Control toolkit and UAT screens through an exact paired SRD tunnel."""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.remote.core_device.hid_service import (
    TOUCHSCREEN_STATE_CONTACT, TOUCHSCREEN_STATE_RELEASE, touch_session,
)
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot

from repair_device_connection import profiles, usb_identity, worker_namespace


async def capture(instance: str, udid: str, output: Path, *, tweaks: bool = False) -> list[str]:
    selected = profiles(instance_name=instance)
    if udid not in selected or (await usb_identity(udid))["udid"] != udid:
        raise RuntimeError("exact USB device and paired profile do not match")
    worker = worker_namespace(selected[udid][1])
    opened = worker["ssh"](
        "/var/jb/usr/bin/uiopen --bundleid com.liquidsky.CrypStore",
        timeout=20, check=False)
    if opened.returncode:
        raise RuntimeError("Control could not be opened on the paired device")
    output.mkdir(parents=True, exist_ok=True)
    files = []
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError("tunnel device identity differs")
        async with DvtProvider(rsd) as provider, Screenshot(provider) as screen:
            async with touch_session(rsd) as touch:
                async def tap(x: int, y: int) -> None:
                    await touch.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, x, y)
                    await asyncio.sleep(.09)
                    await touch.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, x, y)
                    await asyncio.sleep(2)

                async def save(name: str) -> None:
                    path = output / name
                    data = await asyncio.wait_for(screen.get_screenshot(), timeout=15)
                    with path.open("xb") as stream:
                        stream.write(data)
                    files.append(str(path))

                await asyncio.sleep(2)
                await tap(45000, 61400)  # Research Tools tab
                await save("research-current.png")
                await tap(57400, 8200)  # UAT navigation button
                await save("uat-current.png")
                await tap(6200, 5300)  # Return to Research Tools before switching tabs
                if tweaks:
                    await tap(32000, 61400)  # Tweaks tab
                    await touch.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, 45000, 48000)
                    for y in range(45000, 25999, -3000):
                        await asyncio.sleep(.05)
                        await touch.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, 45000, y)
                    await touch.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, 45000, 26000)
                    await asyncio.sleep(2)
                    await save("tweaks-current.png")
                    await tap(12000, 8200)  # Tweaks Security Research category
                    await save("tweaks-security-research.png")
                    await tap(6200, 5300)  # Return to Tweaks before switching tabs
                await tap(21500, 61400)  # Apps tab
                await save("apps-current.png")
                await tap(17000, 5300)  # Apps Security Research category
                await save("apps-security-research.png")
    return files


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance")
    parser.add_argument("udid")
    parser.add_argument("output", type=Path)
    parser.add_argument("--tweaks", action="store_true")
    args = parser.parse_args()
    for item in asyncio.run(capture(args.instance, args.udid, args.output, tweaks=args.tweaks)):
        print(item)
