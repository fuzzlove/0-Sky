#!/usr/bin/env python3
"""Report Control runtime readiness through the existing paired 0-Sky SSH route."""

import argparse
import sys

from register_mounted_app import paired_ssh


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    args = parser.parse_args()
    try:
        ssh = paired_ssh(args.udid)
        command = r'''if [ -r /var/jb/etc/trollstorelite-srd-bridge.token ]; then
 echo TOKEN_READABLE=1
 wc -c < /var/jb/etc/trollstorelite-srd-bridge.token
else echo TOKEN_READABLE=0; fi
/var/jb/usr/bin/python3 --version
echo PYTHON_STATUS=$?
/var/jb/usr/bin/dpkg-query -W -f='${Package} ${Version} ${db:Status-Abbrev}\n' com.liquidskysecurity.srd-runtime-manager ellekit preferenceloader 2>/dev/null
/var/jb/usr/bin/python3 - <<'PY'
import json, pathlib, urllib.request
try:
    token = pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
    request = urllib.request.Request('http://127.0.0.1:48654/v1/status',
        headers={'X-TrollStore-Bridge-Token': token})
    with urllib.request.urlopen(request, timeout=15) as response:
        status = json.load(response)
    keys = ('connected', 'device_bridge', 'paired', 'stage', 'detail', 'age_seconds',
            'device_udid', 'host_identity_verified', 'apple_pairing_verified')
    print('BRIDGE_STATUS=' + json.dumps({key: status.get(key) for key in keys}, sort_keys=True))
    pairing = status.get('pairing', {})
    print('PRIVILEGED_BRIDGE_READY=' + str(pairing.get('privileged_bridge_ready')))
    print('WORKER_FRESH=' + str(pairing.get('worker_fresh')))
    request = urllib.request.Request('http://127.0.0.1:48654/v1/inventory')
    with urllib.request.urlopen(request, timeout=30) as response:
        inventory = json.load(response)
    matches = [item for item in inventory.get('apps', [])
        if 'netfence' in json.dumps(item).lower()]
    print('NETFENCE_APPS=' + json.dumps(matches, sort_keys=True))
except Exception as error:
    print('BRIDGE_UNAVAILABLE=' + str(error))
PY
'''
        result = ssh(command, timeout=30, check=False)
        sys.stdout.write(result.stdout.decode("utf-8", "replace"))
        sys.stderr.write(result.stderr.decode("utf-8", "replace"))
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
