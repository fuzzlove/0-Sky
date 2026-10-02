"""Add ZIP compression normalization to source and configured SRD workers."""
import ast,json,os,subprocess,uuid
from pathlib import Path
from repair_device_connection import HERE,profiles,atomic_write

def patch_source(text):
    if 'def normalize_zip_compression(path):' in text:return text
    helper=(HERE/'ipa_zip_compression.py').read_text()
    anchor='def normalize_ipa_archive(path: pathlib.Path) -> bool:'
    if text.count(anchor)!=1:raise RuntimeError('Unexpected worker archive boundary')
    tree=ast.parse(text);function=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='normalize_ipa_archive')
    lines=text.splitlines(keepends=True)
    fragment=''.join(lines[function.lineno-1:function.end_lineno])
    old='    try:\n        with zipfile.ZipFile(path) as archive:\n'
    if fragment.count(old)!=1:raise RuntimeError('Unexpected ZIP validation boundary')
    fragment=fragment.replace(old,'    recompressed = normalize_zip_compression(path)\n'+old)
    fragment=fragment.replace('    return unwrapped\n','    return unwrapped or recompressed\n')
    lines[function.lineno-1:function.end_lineno]=[helper+'\n\n'+fragment]
    result=''.join(lines).replace('Removed gzip transport wrapper','Normalized IPA transport/compression')
    compile(result,'crypstore_worker.py','exec')
    return result

def sync_host_archive_support(value,output):
    """Apply the archive fix during a repeatable per-device repair."""
    path=next(Path(a) for a in value['ProgramArguments'] if a.endswith('/crypstore_worker.py'))
    old=path.read_bytes();new=patch_source(old.decode()).encode()
    if old==new:return {'changed':False}
    backup=Path(output)/('archive-before-'+uuid.uuid4().hex);backup.mkdir(parents=True,mode=0o700)
    saved=backup/path.name;atomic_write(saved,old)
    mode=path.stat().st_mode&0o777;atomic_write(path,new,mode)
    target=f"gui/{os.getuid()}/{value['Label']}"
    result=subprocess.run(['/bin/launchctl','kickstart','-k',target],capture_output=True,timeout=20)
    if result.returncode:
        atomic_write(path,old,mode)
        subprocess.run(['/bin/launchctl','kickstart','-k',target],capture_output=True,timeout=20)
        raise RuntimeError('Worker restart failed: '+result.stderr.decode()[:500])
    return {'changed':True,'backup':str(saved)}

def main():
    source=HERE.parents[1]/'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py'
    configurations=profiles()
    paths={source:None}
    for _,value in configurations.values():
        paths[next(Path(a) for a in value['ProgramArguments'] if a.endswith('/crypstore_worker.py'))]=value
    backup=HERE/'connection-repair'/('compression-before-'+uuid.uuid4().hex);backup.mkdir(mode=0o700)
    changes=[]
    for path,value in paths.items():
        old=path.read_bytes();new=patch_source(old.decode()).encode()
        if old==new:continue
        saved=backup/(str(len(changes))+'-'+path.name);atomic_write(saved,old)
        changes.append((path,new,old,value,saved))
    atomic_write(backup/'index.json',json.dumps([{'path':str(p),'backup':str(s)} for p,_,_,_,s in changes],indent=2).encode())
    for path,new,old,value,saved in changes:
        mode=path.stat().st_mode&0o777;atomic_write(path,new,mode)
        if value:
            target=f"gui/{os.getuid()}/{value['Label']}"
            result=subprocess.run(['/bin/launchctl','kickstart','-k',target],capture_output=True,timeout=20)
            if result.returncode:
                atomic_write(path,old,mode)
                subprocess.run(['/bin/launchctl','kickstart','-k',target],capture_output=True,timeout=20)
                raise RuntimeError('Worker restart failed: '+result.stderr.decode()[:500])
    print(json.dumps({'changed_files':len(changes),'backup':str(backup)},indent=2))

if __name__=='__main__':main()
