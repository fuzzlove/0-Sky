#!/usr/bin/env python3
"""Tap Link's visible Control-install action on an exact paired SRD."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
from pymobiledevice3.remote.core_device.hid_service import (
    TOUCHSCREEN_STATE_CONTACT, TOUCHSCREEN_STATE_RELEASE, touch_session,
)

from install_link_ui_uat import install_status
from repair_device_connection import profiles, usb_identity, worker_namespace


EVENT_COUNTS = b'''import json,pathlib
path=pathlib.Path('/var/jb/var/log/trollstorelite-srd-bridge.log')
counts={'CONTROL_INSTALL_REQUESTED':0,'CONTROL_INSTALL_VERIFIED':0}
for line in path.read_text(errors='replace').splitlines():
    try:
        row=json.loads(line)
    except ValueError:
        continue
    if isinstance(row,dict) and row.get('event') in counts:
        counts[row['event']]+=1
print(json.dumps(counts))
'''


def event_counts(worker: dict) -> dict:
    result = worker["ssh"]("/var/jb/usr/bin/python3 -", input_data=EVENT_COUNTS,
                           timeout=20, check=False)
    if result.returncode:
        raise RuntimeError("device Bridge event log could not be read")
    return json.loads(result.stdout)


async def capture(instance: str, udid: str, output: Path) -> None:
    selected = profiles(instance_name=instance)
    if udid not in selected or (await usb_identity(udid))["udid"] != udid:
        raise RuntimeError("exact paired profile and USB identity differ")
    worker = worker_namespace(selected[udid][1])
    if install_status(worker).get("action") != "NO_ACTION":
        raise RuntimeError("Control must be verified before the UI action probe")
    before_events = event_counts(worker)
    output.mkdir(parents=True, exist_ok=True)
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError("RemoteXPC selected a different device")
        async with DvtProvider(rsd) as provider, Screenshot(provider) as screenshots:
            (output / "before.png").write_bytes(await asyncio.wait_for(screenshots.get_screenshot(), 15))
            async with touch_session(rsd) as touch:
                await touch.send_touchscreen(TOUCHSCREEN_STATE_CONTACT, 32768, 57800)
                await asyncio.sleep(.07)
                await touch.send_touchscreen(TOUCHSCREEN_STATE_RELEASE, 32768, 57800)
            await asyncio.sleep(4)
            (output / "after.png").write_bytes(await asyncio.wait_for(screenshots.get_screenshot(), 15))
    if install_status(worker).get("action") != "NO_ACTION":
        raise RuntimeError("Control status changed after visible Link action")
    after_events = event_counts(worker)
    if any(after_events.get(name, 0) != before_events.get(name, 0) + 1 for name in
           ("CONTROL_INSTALL_REQUESTED", "CONTROL_INSTALL_VERIFIED")):
        raise RuntimeError("Link tap did not produce one verified Control-install request")
    print({"device": udid[-8:], "before": str(output / "before.png"),
           "after": str(output / "after.png"), "control_action": "NO_ACTION",
           "verified_requests": 1})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--instance-name", required=True)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(capture(args.instance_name, args.udid, args.output))
