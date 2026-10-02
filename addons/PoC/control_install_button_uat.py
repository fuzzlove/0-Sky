#!/usr/bin/env python3
"""Exercise the Link Control-install action on an already healthy paired SRD."""
from __future__ import annotations

import asyncio
import json
import sys

from install_control_ui_uat import remote_json
from repair_device_connection import profiles, usb_identity, worker_namespace


STATUS_AND_INSTALL = r'''
import json,pathlib,urllib.request
token=pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
headers={'X-TrollStore-Bridge-Token':token}
base='http://127.0.0.1:48654/v1/control/install'
def request(method,path):
 req=urllib.request.Request(base+path,headers=headers,method=method)
 with urllib.request.urlopen(req,timeout=60) as response:
  return json.load(response)
before=request('GET','/status')
if before.get('decision',{}).get('action')!='NO_ACTION':
 raise RuntimeError('Control is not healthy before the idempotency probe')
results=[request('POST','') for _ in range(2)]
after=request('GET','/status')
print(json.dumps({'before':before['decision'],'results':[
 {'result':item.get('result'),'stage':item.get('stage'),
  'rollback':item.get('rollback'),'event_count':len(item.get('events',[]))}
 for item in results], 'after':after['decision']}))
'''


def run(instance: str, udid: str) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("exact paired profile and USB identity differ")
    value = remote_json(worker_namespace(selected[udid][1]), STATUS_AND_INSTALL, timeout=150)
    if value.get("after", {}).get("action") != "NO_ACTION" or any(
            row.get("result") != "ALREADY_INSTALLED_AND_VERIFIED" or
            row.get("rollback") != "NOT_NEEDED" for row in value.get("results", [])) or len(value.get("results", [])) != 2:
        raise RuntimeError("repeated Control install action did not remain idempotent")
    return {"device": udid[-8:], **value}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: control_install_button_uat.py INSTANCE EXACT_UDID")
    print(json.dumps(run(sys.argv[1], sys.argv[2]), sort_keys=True))
