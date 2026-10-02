"""Preserve original CodeDirectory identifiers while signing app helpers."""
import json,os,subprocess,uuid
from pathlib import Path
from repair_device_connection import HERE,profiles,atomic_write

def patch_source(text):
    old='        "--generate-entitlement-der",\n'
    new='        "--generate-entitlement-der", "--preserve-metadata=identifier",\n'
    if new in text:return text
    if text.count(old)!=1:raise RuntimeError('Unexpected signing boundary')
    result=text.replace(old,new);compile(result,'crypstore_worker.py','exec');return result

def main():
    root=HERE.parents[1]/'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py'
    paths={root:None}
    for _,value in profiles().values():
        paths[next(Path(a) for a in value['ProgramArguments'] if a.endswith('/crypstore_worker.py'))]=value
    backup=HERE/'connection-repair'/('identity-before-'+uuid.uuid4().hex);backup.mkdir(mode=0o700)
    rows=[]
    for path,value in paths.items():
        old=path.read_bytes();new=patch_source(old.decode()).encode()
        if old==new:continue
        saved=backup/(str(len(rows))+'-'+path.name);atomic_write(saved,old)
        rows.append({'path':str(path),'backup':str(saved)})
        mode=path.stat().st_mode&0o777;atomic_write(path,new,mode)
        if value:
            target=f"gui/{os.getuid()}/{value['Label']}"
            result=subprocess.run(['/bin/launchctl','kickstart','-k',target],capture_output=True,timeout=20)
            if result.returncode:
                atomic_write(path,old,mode)
                subprocess.run(['/bin/launchctl','kickstart','-k',target],capture_output=True,timeout=20)
                raise RuntimeError('Worker restart failed: '+result.stderr.decode()[:500])
    atomic_write(backup/'index.json',json.dumps(rows,indent=2).encode())
    print(json.dumps({'changed_files':len(rows),'backup':str(backup)},indent=2))

if __name__=='__main__':main()
