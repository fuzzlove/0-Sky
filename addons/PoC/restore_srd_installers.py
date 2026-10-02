"""Restore the user-authorized SRD install paths while preserving pairing checks."""
import argparse,json,os,plistlib,subprocess,time,uuid
from pathlib import Path
from repair_device_connection import HERE,profiles,atomic_write

def replace_once(text,old,new):
    if old not in text:return text
    if text.count(old)!=1:raise RuntimeError('Unexpected restoration source')
    return text.replace(old,new)

def restore():
    root=HERE.parents[1]
    bridge=root/'bridge/DeviceRuntime/trollstorelite-srd-bridge.py'
    text=bridge.read_text()
    for signature,argument,operation in [('def queue_install(args):','args[-1]','application-install'),('def install_deb(path):','path','deb-install')]:
        old=signature+'\n    from zero_sky_compat.integration import CompatibilityBlocked, require_install_adapter\n    try:\n        require_install_adapter('+argument+', "'+operation+'")\n    except CompatibilityBlocked as error:\n        return {"status": 193, "stdout": "", "stderr": str(error)}\n'
        text=replace_once(text,old,signature+'\n')
    changes={bridge:text}
    workers=[root/'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py']
    workers += [next(Path(a) for a in v['ProgramArguments'] if a.endswith('/crypstore_worker.py')) for _,v in profiles().values()]
    for path in set(workers):
        text=path.read_text()
        text=replace_once(text,'    compatibility_intake(ipa, "ipa-install")\n','')
        text=replace_once(text,'def process_runtime_sync(job_id: str, request: dict) -> None:\n    from zero_sky_compat.integration import block_legacy_mutation\n    block_legacy_mutation("runtime-sync")\n',
            'def process_runtime_sync(job_id: str, request: dict) -> None:\n')
        changes[path]=text
    builders=[root/'bridge/KitScripts/automation/CrypStoreAutomation/native-install/build_and_install.sh',root/'bridge/KitScripts/runtime-generation/build_and_install.sh']
    builders += [next(Path(a) for a in v['ProgramArguments'] if a.endswith('/crypstore_worker.py')).parent/'native-install/build_and_install.sh' for _,v in profiles().values()]
    for path in set(builders):
        text=path.read_text()
        text=replace_once(text,"# Compatibility admission: retired legacy backend has no validated transaction.\necho 'Compatibility UNKNOWN: legacy installer requires a transactional compatibility adapter.' >&2\nexit 193\n",'')
        text=text.replace('missing Python 3.13; set SRD_PYTHON','missing 0-Sky Python; set SRD_PYTHON')
        text=replace_once(text,'[[ $($PYTHON --version) == Python\\ 3.13.* ]] || { print -u2 \'SRD_PYTHON must be Python 3.13\'; exit 1; }',
            '"$PYTHON" -c \'import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)\' || { print -u2 \'SRD_PYTHON requires Python 3.12 or later\'; exit 1; }')
        changes[path]=text
    release=root/'tools/prepare_release_kit.py'
    text=release.read_text()
    for line in ['        "runtime-generation/install_cryptex_native.py",\n','        "automation/CrypStoreAutomation/native-install/install_cryptex_native.py",\n','        "automation/tools/srd-runtime-manager/sync_runtime_cryptex.py",\n','        "automation/tools/srd-runtime-manager/srd_runtime_manager.py",\n']:
        text=replace_once(text,line,'')
    changes[release]=text
    backup=HERE/'connection-repair'/('installers-before-'+uuid.uuid4().hex);backup.mkdir(mode=0o700)
    changed=[]
    for path,text in changes.items():
        if path.suffix=='.py':compile(text,str(path),'exec')
        if text.encode()==path.read_bytes():continue
        saved=backup/(str(len(changed))+'-'+path.name);atomic_write(saved,path.read_bytes())
        changed.append({'path':str(path),'backup':str(saved)})
    atomic_write(backup/'index.json',json.dumps(changed,indent=2).encode())
    for item in changed:
        path=Path(item['path']);atomic_write(path,changes[path].encode(),path.stat().st_mode & 0o777)
    # The persistent workers must reload the restored install handlers.
    for path,value in profiles().values():
        target=f"gui/{os.getuid()}/{value['Label']}"
        result=subprocess.run(['/bin/launchctl','kickstart','-k',target],capture_output=True,timeout=20)
        if result.returncode:raise RuntimeError('Worker restart failed: '+result.stderr.decode()[:500])
    return {'changed_files':len(changed),'backup':str(backup)}

if __name__=='__main__':print(json.dumps(restore(),indent=2))
