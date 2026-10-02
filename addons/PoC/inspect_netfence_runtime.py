#!/usr/bin/env python3
"""Inspect NetFence package, process and preference readiness without changing rules."""

import argparse
import pathlib
import shlex

from register_mounted_app import paired_ssh


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--copy-binary', action='store_true')
    args = parser.parse_args()
    ssh = paired_ssh(args.udid)
    command = r'''/var/jb/usr/bin/python3 - <<'PY'
import glob, json, os, pathlib, plistlib, subprocess
result = subprocess.run(['/var/jb/usr/bin/dpkg-query', '-W', '-f=${Package} ${Version} ${db:Status-Abbrev}\n'], capture_output=True, text=True)
print('PACKAGES=' + json.dumps([row for row in result.stdout.splitlines() if 'netfence' in row.lower() or 'foxfort' in row.lower()]))
result = subprocess.run(['ps', 'ax', '-o', 'pid=,command='], capture_output=True, text=True)
print('PROCESSES=' + json.dumps([row for row in result.stdout.splitlines() if ('netfence' in row.lower() or 'srd-runtime-manager.py daemon' in row) and 'sh -c' not in row]))
for name in ('/var/mobile/Library/Preferences', '/var/mobile/Library/Application Support/NetFence', '/var/jb/Library/MobileSubstrate/DynamicLibraries/com.foxfort.netfence.bundle', '/var/jb/usr/lib/libfoxfortutils.dylib', '/var/jb/Library/Frameworks/AltList.framework'):
    path = pathlib.Path(name)
    record = {'path': name, 'exists': path.exists()}
    if path.exists():
        stat = path.stat()
        record.update(uid=stat.st_uid, gid=stat.st_gid, mode=oct(stat.st_mode & 0o777))
    print(json.dumps(record))
for directory in ('/var/mobile/Library/Preferences', '/var/jb/Library/MobileSubstrate/DynamicLibraries', '/var/jb/Library/LaunchDaemons', '/var/jb/usr/lib/TweakInject', '/var/jb/usr/libexec'):
    for path in sorted(pathlib.Path(directory).glob('*')):
        if 'netfence' not in path.name.lower():
            continue
        stat = path.stat()
        record = {'path': str(path), 'uid': stat.st_uid, 'gid': stat.st_gid, 'mode': oct(stat.st_mode & 0o777), 'bytes': stat.st_size}
        if path.suffix == '.plist':
            try:
                data = plistlib.loads(path.read_bytes())
                record['keys'] = sorted(data)
                record['daemon_label'] = data.get('Label')
                record['daemon_program'] = data.get('Program') or data.get('ProgramArguments')
            except Exception as error:
                record['plist_error'] = str(error)
        print(json.dumps(record))
PY'''
    result = ssh(command, timeout=60, check=False)
    print(result.stdout.decode('utf-8', 'replace'))
    print(result.stderr.decode('utf-8', 'replace'))
    if args.copy_binary:
        remote = '/private/var/containers/Bundle/Application/1E450B55-EE00-402A-BA86-C6DEE3B72CF0/NetFenceApp.app/NetFenceApp'
        result = ssh('cat ' + shlex.quote(remote), timeout=60)
        destination = pathlib.Path(__file__).parent / 'cryptex-control-netfence-inspect'
        destination.mkdir(exist_ok=True)
        (destination / 'NetFenceApp').write_bytes(result.stdout)
        print('Copied installed NetFence executable for local dependency inspection')


if __name__ == '__main__':
    main()
