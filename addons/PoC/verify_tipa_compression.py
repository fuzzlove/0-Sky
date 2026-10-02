"""Verify every byte in the failed archive survives normalization and ditto."""
import collections,hashlib,json,os,runpy,shutil,subprocess,zipfile
from repair_device_connection import HERE,atomic_write

def inventory(path):
    with zipfile.ZipFile(path) as archive:
        return [(item.filename,item.external_attr,hashlib.sha256(archive.read(item)).hexdigest()) for item in archive.infolist()]

if __name__=='__main__':
    source=HERE.parents[1]/'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py'
    worker=runpy.run_path(str(source))
    original=__import__('pathlib').Path(os.environ['TIPA_INPUT'])
    directory=HERE/'installer-verification/tipa-compression';directory.mkdir(parents=True,exist_ok=True)
    normalized=directory/original.name;shutil.copyfile(original,normalized)
    expected=inventory(original);changed=worker['normalize_ipa_archive'](normalized)
    actual=inventory(normalized)
    if expected!=actual:raise RuntimeError('Archive content/permission preservation failed')
    extracted=directory/'extracted';extracted.mkdir(exist_ok=True)
    subprocess.run(['/usr/bin/ditto','-x','-k',str(normalized),str(extracted)],check=True,timeout=120)
    for name,mode,digest in expected:
        path=extracted/name
        if not name.endswith('/') and hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
            raise RuntimeError('ditto changed member bytes: '+name)
    report={'file':original.name,'normalized':changed,'members_verified':len(expected),'ditto_extraction':'passed','all_payload_bytes_preserved':True}
    atomic_write(directory/'report.json',json.dumps(report,indent=2).encode());print(json.dumps(report,indent=2))
