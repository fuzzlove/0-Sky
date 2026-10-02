"""Read the signature/daemon logs of the current TrollRecorder process only."""
import argparse,asyncio,json
from repair_device_connection import HERE,usb_identity,atomic_write
from device_python import ensure_device_python

async def read(udid):
    await usb_identity(udid)
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.services.os_trace import OsTraceService,OsActivityStreamFlag
    report=json.loads((HERE/'installer-verification/trollrecorder-launch.json').read_text())
    if report['udid']!=udid:raise RuntimeError('Wrong-device PID')
    messages=[]
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid)!=udid:raise RuntimeError('Wrong device')
        async with OsTraceService(rsd) as service:
            async def collect():
                async for entry in service.syslog(pid=report['pid'],stream_flags=int(OsActivityStreamFlag.PROCESS_ONLY|OsActivityStreamFlag.HISTORICAL|OsActivityStreamFlag.DEBUG|OsActivityStreamFlag.INFO|OsActivityStreamFlag.NO_SENSITIVE)):
                    if any(k in entry.message for k in ('[CS]','signature','Signature','Daemon','daemon','Jailbreak')):
                        messages.append(entry.message[-1800:])
            try:await asyncio.wait_for(collect(),timeout=12)
            except asyncio.TimeoutError:pass
    return {'udid':udid,'pid':report['pid'],'messages':messages}

if __name__=='__main__':
    ensure_device_python();p=argparse.ArgumentParser();p.add_argument('--udid',required=True);a=p.parse_args();report=asyncio.run(read(a.udid))
    atomic_write(HERE/'installer-verification/trollrecorder-cslogs.json',json.dumps(report,indent=2).encode());print(json.dumps(report,indent=2))
