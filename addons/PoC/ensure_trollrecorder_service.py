"""Reconcile TrollRecorder's signed SRD daemon on the selected device."""
import argparse
import asyncio
import json
import shlex

from device_python import ensure_device_python
from repair_device_connection import profiles, usb_identity, worker_namespace
from trollrecorder_service_program import PROGRAM


if __name__ == '__main__':
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    args = parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _, profile = profiles()[args.udid]
    ssh = worker_namespace(profile)['ssh']
    listing = ssh('/var/jb/usr/bin/uicache -l', timeout=30).stdout.decode()
    paths = [line.split(' : ',1)[1] for line in listing.splitlines() if line.startswith('wiki.qaq.trapp : ')]
    if len(paths) != 1:
        raise RuntimeError('Ambiguous TrollRecorder registration')
    app = paths[0]
    state = json.loads(ssh('cat /var/jb/var/lib/crypstore/wiki.qaq.trapp.json', timeout=20).stdout)
    mount = ssh(
        "for p in /private/var/run/com.apple.security.cryptexd/mnt/"
        + shlex.quote(state['cryptex_identifier'])
        + ".*/Applications/TRApp.app; do if [ -d \"$p\" ]; then echo \"$p\"; fi; done",
        timeout=20,
    ).stdout.decode().strip().splitlines()
    if len(mount) != 1:
        raise RuntimeError('Ambiguous TrollRecorder Cryptex mount')
    command = '/var/jb/usr/bin/python3 -c ' + shlex.quote(PROGRAM) + ' ' + ' '.join(
        shlex.quote(value) for value in ('wiki.qaq.trapp', app, mount[0])
    )
    result = ssh(command, timeout=100)
    print(json.dumps(json.loads(result.stdout),indent=2))
