#!/usr/bin/env python3
"""Measure Link scene-to-normal-UI time with splash enabled and disabled."""
import argparse
import asyncio
from io import BytesIO
import json
import shlex
import time

from PIL import Image
from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot

from repair_device_connection import profiles, usb_identity, worker_namespace

CONFIG = "/var/jb/etc/0sky-bootsplash.json"
BUNDLE = "codes.liquidsky.research.zerosky"


def remote(namespace, code, *, check=True):
    return namespace["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(code),
                            timeout=20, check=check)


def visible_normal_ui(raw):
    image = Image.open(BytesIO(raw)).convert("RGB")
    w, h = image.size
    # The existing Link UI has a yellow status dot near its upper-left corner.
    # The splash has no yellow pixels there; a repair alert still leaves it
    # visible through the dimmed background.
    for y in range(int(h * .045), int(h * .08), 3):
        for x in range(int(w * .025), int(w * .09), 3):
            r, g, b = image.getpixel((x, y))
            if r > 90 and g > 60 and b < 75 and r > g + 15:
                return True
    return False


async def trial(namespace, screenshots, enabled):
    remote(namespace, "import json,pathlib;pathlib.Path(%r).write_text(json.dumps({'bootsplash':{'enabled':%s,'minimum_display_ms':3000,'maximum_display_ms':5000}}))" %
           (CONFIG, "True" if enabled else "False"))
    namespace["ssh"]("/var/jb/usr/bin/killall ZeroSky", timeout=15, check=False)
    await asyncio.sleep(.4)
    started = time.monotonic()
    opened = namespace["ssh"]("/var/jb/usr/bin/uiopen --bundleid " + BUNDLE,
                              timeout=20, check=False)
    if opened.returncode:
        raise RuntimeError("Link launch failed")
    while time.monotonic() - started < 7:
        raw = await asyncio.wait_for(screenshots.get_screenshot(), timeout=10)
        if visible_normal_ui(raw):
            return round((time.monotonic() - started) * 1000)
        await asyncio.sleep(.12)
    raise RuntimeError("Normal Link UI did not appear within seven seconds")


async def measure(udid):
    await usb_identity(udid)
    namespace = worker_namespace(profiles()[udid][1])
    original = remote(namespace, "import base64,pathlib; p=pathlib.Path(%r); print(base64.b64encode(p.read_bytes()).decode() if p.exists() else 'ABSENT')" % CONFIG).stdout.decode().strip()
    try:
        async with NativeRemotedTunnel(serial=udid) as rsd:
            if str(rsd.udid) != udid:
                raise RuntimeError("Exact-device mismatch")
            async with DvtProvider(rsd) as provider, Screenshot(provider) as screenshots:
                baseline = await trial(namespace, screenshots, False)
                splash = await trial(namespace, screenshots, True)
        return {"device":udid,"baseline_ms":baseline,"splash_ms":splash,
                "delta_ms":splash-baseline}
    finally:
        if original == "ABSENT":
            remote(namespace, "import pathlib;pathlib.Path(%r).unlink(missing_ok=True)" % CONFIG,
                   check=False)
        else:
            remote(namespace, "import base64,pathlib;pathlib.Path(%r).write_bytes(base64.b64decode(%r))" %
                   (CONFIG, original), check=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    args = parser.parse_args()
    print(json.dumps(asyncio.run(measure(args.udid)), indent=2))
