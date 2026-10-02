"""Deploy SDK-prepared asset building to source and configured device workers."""
import json,os,plistlib,subprocess,uuid
from pathlib import Path
from repair_device_connection import HERE,profiles,atomic_write
WRAPPER='''#!/bin/zsh
set -euo pipefail
WORK=${0:A:h}
PYTHON=${SRD_PYTHON:-$(command -v python3)}
[[ -n ${CRYPTEXCTL_UDID:-} ]] || { print -u2 'exact SRD UDID is required'; exit 1; }
[[ -n ${SRDSH_IDENTIFIER:-} && -d ${SRDSH_ROOT:-} ]] || { print -u2 'Cryptex identifier and payload are required'; exit 1; }
"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)'
exec "$PYTHON" "$WORK/install_cryptex_native.py" --build-and-install
'''
def main():
    root=HERE.parents[1];source=HERE/'native_srd_installer.py';code=source.read_bytes();compile(code,str(source),'exec')
    directories=[root/'bridge/KitScripts/automation/CrypStoreAutomation/native-install',root/'bridge/KitScripts/runtime-generation']
    directories += [next(Path(a) for a in v['ProgramArguments'] if a.endswith('/crypstore_worker.py')).parent/'native-install' for _,v in profiles().values()]
    changes={}
    for directory in directories:
        changes[directory/'build_and_install.sh']=WRAPPER.encode()
        changes[directory/'install_cryptex_native.py']=code
    release=root/'tools/prepare_release_kit.py';text=release.read_text()
    anchor='OVERRIDES = {\n'
    rows='    "automation/CrypStoreAutomation/native-install/install_cryptex_native.py": ROOT / "bridge/KitScripts/automation/CrypStoreAutomation/native-install/install_cryptex_native.py",\n    "runtime-generation/install_cryptex_native.py": ROOT / "bridge/KitScripts/runtime-generation/install_cryptex_native.py",\n'
    if rows not in text:text=text.replace(anchor,anchor+rows)
    changes[release]=text.encode()
    backup=HERE/'connection-repair'/('native-before-'+uuid.uuid4().hex);backup.mkdir(mode=0o700)
    records=[]
    for path,data in changes.items():
        if path.exists() and path.read_bytes()==data:continue
        if path.exists():
            saved=backup/(str(len(records))+'-'+path.name);atomic_write(saved,path.read_bytes())
        else:saved=None
        records.append({'path':str(path),'backup':str(saved) if saved else None})
        atomic_write(path,data,0o755)
    atomic_write(backup/'index.json',json.dumps(records,indent=2).encode())
    print(json.dumps({'changed_files':len(records),'backup':str(backup)},indent=2))
if __name__=='__main__':main()
