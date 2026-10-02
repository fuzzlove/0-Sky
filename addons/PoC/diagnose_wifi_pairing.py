#!/usr/bin/env python3
"""Read nonsecret pairing state from one exact enrolled SRD and its Mac worker."""
import argparse
import asyncio
import json
from pathlib import Path
import shlex

from repair_device_connection import profiles, usb_identity, worker_namespace

REMOTE = r'''import json,pathlib,urllib.request
worker_path=pathlib.Path('/var/jb/var/run/crypstore-worker.json')
worker=json.loads(worker_path.read_text()) if worker_path.exists() else {}
keys=('timestamp','connected','pairing_state','pairing_error','transport_type',
      'transport_state','session_state','usb_available','wifi_available',
      'wifi_lockdown_enabled','wifi_pairing_verified','wireless_connected',
      'remote_pairing_ready','wireless_rsd_verified','apple_pairing_verified',
      'lockdown_session_validated','host_identity_verified')
result={'worker':{key:worker.get(key) for key in keys}}
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
request=urllib.request.Request('http://127.0.0.1:48654/v1/pairing/status',
 headers={'X-TrollStore-Bridge-Token':token})
with urllib.request.urlopen(request,timeout=5) as response:
 status=json.load(response)
result['bridge']={key:status.get(key) for key in (
 'paired','relationship_verified','worker_fresh','pairing_state','pairing_error',
 'usb_pairing_verified','wifi_pairing_verified','wifi_available',
 'wifi_lockdown_state','remote_pairing_state','wireless_rsd_state',
 'transport_type','transport_state','session_state','wireless_connected','message')}
print(json.dumps(result))'''


async def diagnose(udid: str, allow_wireless: bool = False) -> None:
    if not allow_wireless:
        await usb_identity(udid)
    namespace = worker_namespace(profiles()[udid][1])
    response = namespace["ssh"](
        "/var/jb/usr/bin/python3 -c " + shlex.quote(REMOTE),
        timeout=20, check=True,
    )
    result = json.loads(response.stdout)
    receipts = []
    root = Path.home() / "Library/Application Support/0-Sky/instances"
    for receipt in root.glob("*/pairing-state.json"):
        try:
            state = json.loads(receipt.read_text())
        except (OSError, ValueError):
            continue
        if state.get("device_udid") != udid:
            continue
        wireless = state.get("wireless") or {}
        receipts.append({key: wireless.get(key) for key in
                         ("status", "errorCode", "transport", "wifiLockdownEnabled",
                          "wifiPairingVerified", "remotePairingReady", "wirelessRSDVerified")})
    result["mac_receipts"] = receipts
    print(json.dumps({"device": udid, **result}, indent=2, sort_keys=True))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--allow-wireless", action="store_true")
    args = parser.parse_args()
    asyncio.run(diagnose(args.udid, args.allow_wireless))
