#!/usr/bin/env python3
"""Make the existing runtime helper find Homebrew dpkg-deb under launchd."""

import argparse
import os
import pathlib
import shutil
import subprocess

from register_mounted_app import paired_ssh


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--deploy', action='store_true')
    args = parser.parse_args()
    paired_ssh(args.udid)
    path = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
    tool = shutil.which('dpkg-deb', path=path)
    if not tool:
        raise RuntimeError('dpkg-deb is not installed in the supported host tool locations')
    subprocess.run([tool, '--version'], env={'PATH': '/usr/bin:/bin'}, check=True)
    target = pathlib.Path(os.environ['CRYPSTORE_INSTANCE_DIR']) / 'automation/tools/srd-runtime-manager/sync_runtime_cryptex.py'
    original = target.read_text()
    old = 'dpkg_deb = shutil.which("dpkg-deb")'
    new = 'dpkg_deb = shutil.which("dpkg-deb", path="/opt/homebrew/bin:/usr/local/bin:" + os.environ.get("PATH", "/usr/bin:/bin"))'
    if new in original:
        print('RUNTIME_TOOL_PATH_ALREADY_REPAIRED')
        return
    if original.count(old) != 1:
        raise RuntimeError('runtime helper differs from the diagnosed version')
    repaired = original.replace(old, new, 1)
    compile(repaired, str(target), 'exec')
    print('RUNTIME_TOOL_PATH_CHECK_SUCCESS')
    if args.deploy:
        backup = target.with_name(target.name + '.before-tool-path-repair')
        if backup.exists():
            raise RuntimeError('backup already exists; inspect it before replacing the helper')
        shutil.copy2(target, backup)
        temporary = target.with_name(target.name + '.repair-new')
        temporary.write_text(repaired)
        shutil.copymode(target, temporary)
        os.replace(temporary, target)
        print('RUNTIME_TOOL_PATH_REPAIR_DEPLOYED')


if __name__ == '__main__':
    main()
