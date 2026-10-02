#!/usr/bin/env python3
"""Run the installed 0-Sky toolkit suite on one exact paired USB SRD."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import plistlib
import shlex
import sys
import time

from device_python import ensure_device_python
from repair_device_connection import atomic_write, profiles, usb_identity, worker_namespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'bridge/DeviceRuntime'))
from zero_sky_core.research_toolkit_runner import overall_result


REMOTE = r'''import http.client,json,time,uuid
with open('/var/jb/etc/trollstorelite-srd-bridge.token',encoding='ascii') as stream:
 token=stream.read().strip()
def call(operation):
 request={'protocolVersion':1,'requestId':str(uuid.uuid4()),'timestamp':time.time(),
          'operation':operation,'parameters':{}}
 connection=http.client.HTTPConnection('127.0.0.1',48654,timeout=90)
 try:
  connection.request('POST','/v1/core',json.dumps(request),
                     {'Content-Type':'application/json','X-TrollStore-Bridge-Token':token})
  response=connection.getresponse()
  payload=response.read(2097153)
  if len(payload)>2097152: raise RuntimeError('toolkit response exceeds limit')
  return {'http_status':response.status,'body':json.loads(payload)}
 finally: connection.close()
print(json.dumps({'suite':call('runToolkitUAT'),
                  'inventory':call('getResearchToolkit')}))
'''


def run(udid: str, instance_name: str) -> dict:
    identity = asyncio.run(usb_identity(udid))
    path, _ = profiles(instance_name=instance_name)[udid]
    namespace = worker_namespace(plistlib.loads(path.read_bytes()))
    response = namespace['ssh']('/var/jb/usr/bin/python3 -c ' + shlex.quote(REMOTE),
                                timeout=120, check=False)
    if response.returncode:
        raise RuntimeError('paired SSH toolkit request failed: ' +
                           response.stderr.decode('utf-8', 'replace')[-500:])
    value = json.loads(response.stdout)
    suite = value.get('suite', {})
    inventory = value.get('inventory', {})
    if suite.get('http_status') != 200 or suite.get('body', {}).get('success') is not True:
        raise RuntimeError('device Core toolkit request failed: ' +
                           str(suite.get('body', {}).get('errorCode', suite.get('http_status'))))
    if inventory.get('http_status') != 200 or inventory.get('body', {}).get('success') is not True:
        raise RuntimeError('device toolkit inventory failed: ' +
                           str(inventory.get('body', {}).get('errorCode', inventory.get('http_status'))))
    snapshot = inventory['body']['result']
    if not isinstance(snapshot, dict) or not isinstance(snapshot.get('components'), list):
        raise RuntimeError('device toolkit inventory is incomplete')
    result = suite['body']['result']
    if not isinstance(result, dict) or not isinstance(result.get('smoke'), dict) or not isinstance(result.get('uat'), dict):
        raise RuntimeError('device toolkit response is incomplete')
    public_identity = {key: identity[key] for key in ('product', 'version', 'build')}
    public_identity['device_reference'] = hashlib.sha256(udid.encode()).hexdigest()[:16]
    public_identity['usb_identity_verified'] = True
    return {'device': public_identity, 'collected_at': int(time.time()),
            'result': result, 'inventory': snapshot,
            'verified_overall': overall_result(result['smoke'], result['uat'])}


def main() -> int:
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--instance-name', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    value = run(args.udid, args.instance_name)
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    atomic_write(args.output, (json.dumps(value, indent=2, sort_keys=True) + '\n').encode())
    result = value['result']
    print(json.dumps({'device_model': value['device']['product'],
                      'ios_build': value['device']['build'],
                      'inventory_components': len(value['inventory']['components']),
                      'overall': value['verified_overall'],
                      'device_reported_overall': result.get('overall'),
                      'smoke_counts': result.get('smoke', {}).get('counts'),
                      'uat_counts': result.get('uat', {}).get('counts'),
                      'report': result.get('report')}, sort_keys=True))
    return 0 if value['verified_overall'] == 'PASS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
