#!/usr/bin/env python3
"""Compare the running SRD Link binary to the locally built IPA."""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import zipfile

from repair_device_connection import HERE, profiles, worker_namespace

IPA = HERE.parents[1] / "link/dist/0-Sky-Link-1.9.0-source.ipa"
PROGRAM = r'''import hashlib,json,pathlib,plistlib,subprocess
rows=subprocess.check_output(['/bin/ps','-axo','command='],text=True).splitlines()
apps=[pathlib.Path(row.strip()) for row in rows if row.strip().endswith('/ZeroSky.app/ZeroSky')]
answer=[]
for executable in apps:
 app=executable.parent
 info=plistlib.loads((app/'Info.plist').read_bytes())
 source=executable.read_bytes()
 answer.append({'build':info.get('CFBundleVersion'),'version':info.get('CFBundleShortVersionString'),
                'binary_sha256':hashlib.sha256(source).hexdigest(),
                'splash_symbol':b'ZSSplashController' in source,
                'app_path':str(app)})
print(json.dumps(answer))'''


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--udid', required=True)
    parser.add_argument('--instance-name')
    args = parser.parse_args()
    with zipfile.ZipFile(IPA) as archive:
        data = archive.read('Payload/ZeroSky.app/ZeroSky')
    expected = hashlib.sha256(data).hexdigest()
    namespace = worker_namespace(profiles(instance_name=args.instance_name)[args.udid][1])
    observed = json.loads(namespace['ssh']('/var/jb/usr/bin/python3 -c ' + shlex.quote(PROGRAM),
                                      timeout=20).stdout)
    print(json.dumps({'expected_ipa_sha256': expected, 'running': observed}, indent=2))
