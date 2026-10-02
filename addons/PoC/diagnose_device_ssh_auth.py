"""Inspect SSH server failure reasons using one deliberately invalid password."""
import argparse
import asyncio
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from device_python import ensure_device_python
from repair_device_connection import HOST_TOOLS, profiles, usb_identity


async def diagnose(udid):
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.os_trace import OsTraceService
    await usb_identity(udid)
    sys.path.insert(0,str(HOST_TOOLS))
    import pair
    _,profile=profiles()[udid]
    env=profile["EnvironmentVariables"]
    if not pair.exact_iproxy_present(udid,env["CRYPSTORE_DEVICE_PORT"]):
        raise RuntimeError("No exact-device USB route")
    base=pair.ssh_base(env["CRYPSTORE_DEVICE_HOST"],env["CRYPSTORE_DEVICE_PORT"],
        Path(env["CRYPSTORE_DEVICE_KEY"]),known_hosts=Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"]),
        host_alias=env["CRYPSTORE_DEVICE_HOST_ALIAS"])
    base=[x.replace("BatchMode=yes","BatchMode=no").replace("PasswordAuthentication=no","PasswordAuthentication=yes") for x in base]
    base[1:1]=["-o","PubkeyAuthentication=no","-o","PreferredAuthentications=password","-o","NumberOfPasswordPrompts=1"]
    lines=[]
    async with await create_using_usbmux(serial=udid,connection_type="USB",autopair=False) as device:
        async with OsTraceService(device) as trace:
            async def collect():
                async for entry in trace.syslog():
                    if "dropbear" in entry.filename.lower() and any(x in entry.message.lower() for x in ("password","locked","auth")):
                        lines.append(entry.message)
            logger=asyncio.create_task(collect())
            await asyncio.sleep(1)
            with tempfile.TemporaryDirectory(prefix="0sky-auth-diagnostic-") as folder:
                helper=Path(folder)/"askpass"
                helper.write_text("#!/bin/sh\nprintf '%s\\n' '0sky-deliberately-invalid-diagnostic-password'\n")
                helper.chmod(0o700)
                process=await asyncio.create_subprocess_exec(*base,"id -u",
                    env={**os.environ,"SSH_ASKPASS":str(helper),"SSH_ASKPASS_REQUIRE":"force","DISPLAY":"0sky-diagnostic"},
                    stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                await asyncio.wait_for(process.communicate(),timeout=20)
                await asyncio.sleep(3)
            logger.cancel()
            try: await logger
            except asyncio.CancelledError: pass
    print("\n".join(lines) or "No SSH authentication reason was emitted in the public device logs")


if __name__=="__main__":
    ensure_device_python()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid",required=True)
    args=parser.parse_args()
    asyncio.run(diagnose(args.udid))
