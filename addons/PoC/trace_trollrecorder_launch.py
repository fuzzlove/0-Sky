"""Observe TrollRecorder's own signature diagnostics during one relaunch."""
import argparse,asyncio,json,time
from repair_device_connection import HERE,atomic_write,usb_identity
from device_python import ensure_device_python

async def trace(udid):
    await usb_identity(udid)
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.services.dvt.instruments.dvt_provider import DvtProvider
    from pymobiledevice3.services.dvt.instruments.process_control import ProcessControl
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid)!=udid:raise RuntimeError('Device identity mismatch')
        async with DvtProvider(rsd) as provider, ProcessControl(provider) as control:
            pid=await control.launch('wiki.qaq.trapp')
            messages=[]
            async def collect():
                async for event in control:
                    if any(k in event.message for k in ('[CS]','signature','Signature','daemon','Daemon','Jailbreak')):
                        messages.append(event.message[-1500:])
            try:await asyncio.wait_for(collect(),timeout=12)
            except asyncio.TimeoutError:pass
    return {'udid':udid,'pid':pid,'messages':messages}

if __name__=='__main__':
    ensure_device_python();p=argparse.ArgumentParser();p.add_argument('--udid',required=True);a=p.parse_args()
    report=asyncio.run(trace(a.udid));atomic_write(HERE/'installer-verification/trollrecorder-launch.json',json.dumps(report,indent=2).encode());print(json.dumps(report,indent=2))
