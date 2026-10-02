"""Capture the current SRD screen through its existing developer service."""
import argparse,asyncio
from pathlib import Path
from repair_device_connection import usb_identity
from device_python import ensure_device_python

async def capture(udid,path):
    await usb_identity(udid)
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
    from pymobiledevice3.services.dvt.instruments.screenshot import Screenshot
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid)!=udid:raise RuntimeError('Exact-device mismatch')
        async with DvtProvider(rsd) as provider, Screenshot(provider) as service:
            raw=await asyncio.wait_for(service.get_screenshot(),timeout=30)
    Path(path).write_bytes(raw);print(str(path))

if __name__=='__main__':
    ensure_device_python();p=argparse.ArgumentParser();p.add_argument('--udid',required=True);p.add_argument('--output',required=True);a=p.parse_args()
    asyncio.run(capture(a.udid,a.output))
