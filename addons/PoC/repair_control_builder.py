#!/usr/bin/env python3
"""Verify and deploy the Control cryptex image-builder repair."""

import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess

from register_mounted_app import paired_ssh

EXPECTED = {
    'build_and_install.sh': 'ecefe48507e0315cc8ab3cd39e4c168c41f8149832170ecb491fbd9e7df91515',
    'install_cryptex_native.py': 'b33ac27bb17bfc6b84ab81abf228436a228af03864e460674d4f5536479f1581',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--deploy', action='store_true')
    parser.add_argument('--retry-netfence', action='store_true')
    args = parser.parse_args()
    ssh = paired_ssh(args.udid)
    here = pathlib.Path(__file__).resolve().parent
    native = pathlib.Path(os.environ['CRYPSTORE_INSTANCE_DIR']) / 'automation/CrypStoreAutomation/native-install'
    fixed = here / 'control-builder-fix'
    if args.check:
        check = here / 'cryptex-control-builder-check'
        attempt = 2
        while check.exists():
            check = here / f'cryptex-control-builder-check-{attempt}'
            attempt += 1
        check.mkdir()
        for name in (*EXPECTED, 'generate_trust_cache.py', 'BuildManifest.plist'):
            shutil.copy2((fixed if name in EXPECTED else native) / name, check / name)
        env = os.environ.copy()
        env.update(SRDSH_ROOT=str(here / 'cryptex-control-signed-stage/dstroot'),
                   SRDSH_BUILD_MANIFEST=str(check / 'BuildManifest.plist'),
                   SRDSH_BUILD_ONLY='1', SRDSH_IDENTIFIER='com.liquidsky.control.buildercheck',
                   SRDSH_VERSION='1.0', CRYPTEXCTL_UDID=args.udid)
        subprocess.run([str(check / 'build_and_install.sh')], env=env, cwd=check, check=True)
        (fixed / 'verified-build.txt').write_text(str(check))
        print('BUILDER_CHECK_SUCCESS', flush=True)
    if args.deploy:
        pointer = fixed / 'verified-build.txt'
        check = pathlib.Path(pointer.read_text()) if pointer.is_file() else here / 'missing-check'
        if (not check.is_relative_to(here) or
                not (check / 'srdsh-apfs-sealed-udzo.dmg').is_file() or
                any((check / name).read_bytes() != (fixed / name).read_bytes() for name in EXPECTED)):
            raise RuntimeError('complete --check before deployment')
        for name, expected in EXPECTED.items():
            destination = native / name
            if destination.read_bytes() == (fixed / name).read_bytes():
                continue
            if hashlib.sha256(destination.read_bytes()).hexdigest() != expected:
                raise RuntimeError('installed tool changed since diagnosis: ' + name)
            backup = destination.with_name(name + '.before-apfs-repair')
            if backup.exists():
                raise RuntimeError('backup already exists: ' + name)
            shutil.copy2(destination, backup)
            temporary = destination.with_name(name + '.repair-new')
            shutil.copy2(fixed / name, temporary)
            os.replace(temporary, destination)
        print('BUILDER_REPAIR_DEPLOYED', flush=True)
    if args.retry_netfence:
        if any((native / name).read_bytes() != (fixed / name).read_bytes() for name in EXPECTED):
            raise RuntimeError('deploy the verified builder before retrying')
        command = r'''/var/jb/usr/bin/python3 - <<'PY'
import json, pathlib, urllib.request
source = '/var/mobile/tmp/B83F5680-8276-474A-9085-B7BB50E39234.ipa'
if not pathlib.Path(source).is_file():
    raise SystemExit('NetFence temporary package is unavailable; reselect it in Control.')
token = pathlib.Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
request = urllib.request.Request('http://127.0.0.1:48654/v1/trollstore',
    data=json.dumps({'arguments': ['install', 'custom', source]}).encode(),
    headers={'X-TrollStore-Bridge-Token': token, 'Content-Type': 'application/json'})
with urllib.request.urlopen(request, timeout=1850) as response:
    result = json.load(response)
print(json.dumps(result, indent=2))
raise SystemExit(0 if result.get('status') == 0 else 1)
PY'''
        print('Retrying the saved NetFence request through the authenticated bridge', flush=True)
        result = ssh(command, timeout=1900, check=False)
        print(result.stdout.decode('utf-8', 'replace'), flush=True)
        print(result.stderr.decode('utf-8', 'replace'), flush=True)
        if result.returncode:
            raise RuntimeError('NetFence bridge retry failed')


if __name__ == '__main__':
    main()
