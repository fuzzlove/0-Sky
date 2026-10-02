#!/usr/bin/env python3
"""Verify the registered Link build on an exact enrolled SRD."""
import argparse
import asyncio
import json

from repair_device_connection import profiles, usb_identity, worker_namespace

BUNDLE = "codes.liquidsky.research.zerosky"
PROBE = """import json,pathlib,plistlib,subprocess
prefix='codes.liquidsky.research.zerosky : '
lines=subprocess.check_output(['/var/jb/usr/bin/uicache','-l'],text=True).splitlines()
paths=[line[len(prefix):].strip() for line in lines if line.startswith(prefix)]
if len(paths)!=1: raise SystemExit('Expected one registered Link app')
p=pathlib.Path(paths[0]); info=plistlib.loads((p/'Info.plist').read_bytes())
print(json.dumps({'version':info.get('CFBundleShortVersionString'),
                  'build':info.get('CFBundleVersion'),
                  'binary_present':(p/'ZeroSky').is_file()}))
"""


async def verify(udid: str, instance_name: str | None = None) -> None:
    await usb_identity(udid)
    namespace = worker_namespace(profiles(instance_name=instance_name)[udid][1])
    result = namespace["ssh"](
        "/var/jb/usr/bin/python3 -c " + __import__("shlex").quote(PROBE),
        timeout=25, check=True,
    )
    info = json.loads(result.stdout)
    if (info["version"], info["build"], info["binary_present"]) != ("1.9.0", "47", True):
        raise RuntimeError("Unexpected registered Link build")
    print(json.dumps({"device": udid, "link_build": "47", "status": "PASS"}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name")
    args = parser.parse_args()
    asyncio.run(verify(args.udid, args.instance_name))
