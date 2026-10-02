#!/usr/bin/env python3
"""Exercise the same authenticated pair request used by 0-Sky Link."""
import argparse
import asyncio
import json
import shlex
import time

from repair_device_connection import profiles, usb_identity, worker_namespace

REMOTE = r'''import json,pathlib,sys,urllib.request
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
path=sys.argv[1]
request=urllib.request.Request('http://127.0.0.1:48654'+path,
 headers={'X-TrollStore-Bridge-Token':token},
 data=b'' if path=='/v1/pairing/request' else None,
 method='POST' if path=='/v1/pairing/request' else 'GET')
with urllib.request.urlopen(request,timeout=10) as response:
 print(response.read().decode())'''


def request(namespace: dict, path: str) -> dict:
    command = "/var/jb/usr/bin/python3 -c " + shlex.quote(REMOTE) + " " + shlex.quote(path)
    result = namespace["ssh"](command, timeout=20, check=True)
    return json.loads(result.stdout)


async def verify(udid: str) -> None:
    await usb_identity(udid)
    namespace = worker_namespace(profiles()[udid][1])
    before = request(namespace, "/v1/pairing/status")
    if not (before.get("paired") and before.get("wifi_pairing_verified")):
        raise RuntimeError("Existing trusted relationship is not ready for revalidation")
    queued = request(namespace, "/v1/pairing/request")
    if queued.get("status") != 0 or not queued.get("job_id"):
        raise RuntimeError(f"Pairing request failed to queue: {queued.get('errorCode')}")
    job_id = queued["job_id"]
    for _ in range(75):
        time.sleep(2)
        result = request(namespace, "/v1/pairing/result?job_id=" + job_id)
        if not result.get("complete"):
            continue
        value = result.get("result", result)
        print(json.dumps({"device": udid, "status": value.get("status"),
                          "errorCode": value.get("errorCode"),
                          "stderr": value.get("stderr")}, indent=2))
        if value.get("status") != 0:
            raise SystemExit(1)
        for _ in range(15):
            after = request(namespace, "/v1/pairing/status")
            if (after.get("paired") and after.get("wifi_pairing_verified") and
                    (before.get("wireless_rsd_state") != "VERIFIED" or
                     after.get("wireless_rsd_state") == "VERIFIED")):
                return
            time.sleep(1)
        raise RuntimeError("Pair job succeeded without retaining live Wi-Fi/RSD trust state")
    raise TimeoutError("Pairing job did not complete in 150 seconds")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    asyncio.run(verify(parser.parse_args().udid))
