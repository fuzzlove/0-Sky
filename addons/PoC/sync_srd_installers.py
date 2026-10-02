"""Keep each configured worker's native SRD builders aligned with source."""
import json,uuid
from pathlib import Path
from repair_device_connection import HERE,atomic_write

def sync_host_installers(value,output):
    worker=next(Path(a) for a in value['ProgramArguments'] if a.endswith('/crypstore_worker.py'))
    source=HERE.parents[1]/'bridge/KitScripts/automation/CrypStoreAutomation/native-install'
    changes=[]
    for name in ('build_and_install.sh','install_cryptex_native.py'):
        target=worker.parent/'native-install'/name
        if target.parent.is_symlink() or target.is_symlink():raise RuntimeError('Unsafe worker native installer path')
        raw=(source/name).read_bytes()
        if name.endswith('.py'):compile(raw,str(target),'exec')
        old=target.read_bytes() if target.exists() else None
        if old!=raw:changes.append((target,raw,old))
    if not changes:return {'changed':False}
    backup=Path(output)/('installer-before-'+uuid.uuid4().hex);backup.mkdir(mode=0o700,parents=True)
    records=[]
    for index,(path,raw,old) in enumerate(changes):
        saved=backup/(str(index)+'-'+path.name)
        if old is not None:atomic_write(saved,old)
        records.append({'path':str(path),'backup':str(saved) if old is not None else None})
    atomic_write(backup/'index.json',json.dumps(records,indent=2).encode())
    written=[]
    try:
        for path,raw,old in changes:
            path.parent.mkdir(parents=True,exist_ok=True)
            atomic_write(path,raw,0o755);written.append((path,old))
    except Exception:
        for path,old in reversed(written):
            if old is None:path.unlink()
            else:atomic_write(path,old,0o755)
        raise
    return {'changed':True,'backup':str(backup),'file_count':len(changes)}
