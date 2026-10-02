#!/usr/bin/env python3
"""Capture real 0-Sky splash frames and its final Link scene on one SRD."""
import argparse
import asyncio
import base64
import json
from pathlib import Path
import shlex
import time

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.remote.core_device.hid_service import (
    TOUCHSCREEN_STATE_CONTACT, TOUCHSCREEN_STATE_RELEASE, touch_session,
)

from repair_device_connection import profiles, usb_identity, worker_namespace


async def capture(udid, output, instance_name=None):
    await usb_identity(udid)
    namespace = worker_namespace(profiles(instance_name=instance_name)[udid][1])
    output.mkdir(parents=True, exist_ok=True)
    def run(code):
        return namespace['ssh']('/var/jb/usr/bin/python3 -c ' + shlex.quote(code),
                                timeout=20)
    config = '/var/jb/etc/0sky-bootsplash.json'
    original = run('import base64,pathlib;p=pathlib.Path(%r);print(base64.b64encode(p.read_bytes()).decode() if p.exists() else "ABSENT")' % config).stdout.decode().strip()
    try:
        run('import json,pathlib;pathlib.Path(%r).write_text(json.dumps({"bootsplash":{"enabled":True,"minimum_display_ms":3000,"maximum_display_ms":5000}}))' % config)
        async with NativeRemotedTunnel(serial=udid) as rsd:
            if str(rsd.udid) != udid:
                raise RuntimeError("Exact device mismatch")
            async with DvtProvider(rsd) as provider, Screenshot(provider) as screenshots:
                stopped = namespace['ssh']('/var/jb/usr/bin/killall ZeroSky', timeout=15,
                                           check=False)
                print({'kill_exit': stopped.returncode}, flush=True)
                await asyncio.sleep(.8)
                started = time.monotonic()
                opened = namespace['ssh']('/var/jb/usr/bin/uiopen --bundleid codes.liquidsky.research.zerosky',
                                          timeout=20, check=False)
                if opened.returncode:
                    raise RuntimeError("Link could not be opened")
                await asyncio.sleep(1)
                start_image = await asyncio.wait_for(screenshots.get_screenshot(), timeout=10)
                destination = output / "start.png"
                destination.write_bytes(start_image)
                print(destination, flush=True)
                async with touch_session(rsd) as touch:
                    await touch.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, 32768, 41700)
                    await asyncio.sleep(.07)
                    await touch.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, 32768, 41700)
                for index in range(8):
                    image = await asyncio.wait_for(screenshots.get_screenshot(), timeout=10)
                    ms = int((time.monotonic() - started) * 1000)
                    destination = output / f"frame-{index}-{ms}ms.png"
                    destination.write_bytes(image)
                    print(destination, flush=True)
                    await asyncio.sleep(.7)
    finally:
        if original == 'ABSENT':
            run('import pathlib;pathlib.Path(%r).unlink(missing_ok=True)' % config)
        else:
            run('import base64,pathlib;pathlib.Path(%r).write_bytes(base64.b64decode(%r))' %
                (config, original))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--instance-name')
    args = parser.parse_args()
    asyncio.run(capture(args.udid, args.output, args.instance_name))
