#!/usr/bin/env python3
"""Read the paired SRD's authenticated 0-Sky runtime health without exporting its token."""
import argparse
import asyncio
import json
import shlex

from repair_device_connection import profiles, usb_identity, worker_namespace

REMOTE = """import json,pathlib,urllib.request
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
request=urllib.request.Request('http://127.0.0.1:48654/v1/runtime',
 headers={'X-TrollStore-Bridge-Token':token})
with urllib.request.urlopen(request,timeout=15) as response:
 print(response.read().decode())
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, profile = profiles(instance_name=args.instance_name)[args.udid]
    ssh = worker_namespace(profile)["ssh"]
    result = ssh("/var/jb/usr/bin/python3 -c " + shlex.quote(REMOTE), timeout=30)
    value = json.loads(result.stdout)
    print(json.dumps(value, indent=2))


if __name__ == "__main__":
    main()
