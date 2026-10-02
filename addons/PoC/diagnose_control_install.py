#!/usr/bin/env python3
"""Read recent Control install diagnostics over its paired SSH route."""

import argparse
import os
import pathlib
import sys

from register_mounted_app import paired_ssh


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    args = parser.parse_args()
    ssh = paired_ssh(args.udid)
    result = ssh("tail -45 /var/jb/var/log/trollstorelite-srd-bridge.log; "
                 "ls -lt /var/jb/var/spool/crypstore/jobs 2>/dev/null | head -8",
                 timeout=30, check=False)
    sys.stdout.write(result.stdout.decode('utf-8', 'replace'))
    sys.stderr.write(result.stderr.decode('utf-8', 'replace'))
    instance = pathlib.Path(os.environ['CRYPSTORE_INSTANCE_DIR'])
    for log in sorted((instance / 'logs').glob('*worker*log')):
        print(f'HOST_LOG={log.name}')
        print('\n'.join(log.read_text(errors='replace').splitlines()[-30:]))


if __name__ == '__main__':
    main()
