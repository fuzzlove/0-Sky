"""Stamp verified SRD MCM installs with TrollStore ownership metadata."""
import json
import os
import subprocess
import uuid
from pathlib import Path

from repair_device_connection import HERE, atomic_write, profiles


FRAGMENT = '''def mark_trollstore_owned_mcm(bundle_id: str, registered_app: str,
                             cryptex_app: str, executable: str) -> None:
    """Mark only a verified, byte-identical MCM copy; never alter signed code."""
    verifier = r\'''import hashlib,os,pathlib,plistlib,stat,sys
bundle_id,registered_app,cryptex_app,executable=sys.argv[1:]
app=pathlib.Path(registered_app);container=app.parent
if app.is_symlink() or container.is_symlink() or container.parent!=pathlib.Path('/private/var/containers/Bundle/Application'):
 raise SystemExit('Unexpected MCM app path')
if not app.is_dir():raise SystemExit('MCM app is missing')
with (app/'Info.plist').open('rb') as f:info=plistlib.load(f)
with (container/'.com.apple.mobile_container_manager.metadata.plist').open('rb') as f:metadata=plistlib.load(f)
if info.get('CFBundleIdentifier')!=bundle_id or metadata.get('MCMMetadataIdentifier')!=bundle_id:
 raise SystemExit('MCM bundle identity mismatch')
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.digest()
if sha(app/executable)!=sha(pathlib.Path(cryptex_app)/executable):
 raise SystemExit('MCM executable differs from authorized Cryptex')
marker=container/'_TrollStore'
if marker.is_symlink():raise SystemExit('Unsafe ownership marker')
if marker.exists():
 metadata=os.stat(marker,follow_symlinks=False)
 if not stat.S_ISREG(metadata.st_mode) or metadata.st_size!=0:raise SystemExit('Unexpected ownership marker')
else:
 owner=container.stat()
 fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
 try:os.fchown(fd,owner.st_uid,owner.st_gid)
 finally:os.close(fd)
print(str(marker))
\'''
    command = (
        '/var/jb/usr/bin/python3 -c ' + shlex.quote(verifier) + ' '
        + ' '.join(shlex.quote(value) for value in
                   (bundle_id, registered_app, cryptex_app, executable))
    )
    result = ssh(command, timeout=60)
    marker = result.stdout.decode('utf-8', 'replace').strip()
    if marker != str(pathlib.Path(registered_app).parent / '_TrollStore'):
        raise RuntimeError('MCM ownership marker verification failed')
    log('verified TrollStore ownership marker in MCM container')


'''


def patch_source(source: str) -> str:
    signature = 'def mark_trollstore_owned_mcm('
    definition_point = 'def register_and_link(bundle_id: str, executable: str, app_name: str, mount: str,'
    call_point = '    verify_foreground_launch(bundle_id, registered_app, executable)\n    return registered_app'
    replacement = (
        '    mark_trollstore_owned_mcm(bundle_id, registered_app, cryptex_app, executable)\n'
        + call_point
    )
    if signature not in source:
        if source.count(definition_point) != 1:
            raise RuntimeError('Unexpected registration definition')
        source = source.replace(definition_point, FRAGMENT + definition_point)
    if '    mark_trollstore_owned_mcm(bundle_id, registered_app, cryptex_app, executable)' not in source:
        if source.count(call_point) != 1:
            raise RuntimeError('Unexpected launch verification boundary')
        source = source.replace(call_point, replacement)
    compile(source, 'crypstore_worker.py', 'exec')
    return source


def main():
    canonical = HERE.parents[1] / 'bridge/KitScripts/automation/CrypStoreAutomation/crypstore_worker.py'
    paths = {canonical: None}
    for _, profile in profiles().values():
        worker = next(Path(a) for a in profile['ProgramArguments'] if a.endswith('/crypstore_worker.py'))
        paths[worker] = profile
    planned = []
    for path, profile in paths.items():
        old = path.read_bytes()
        new = patch_source(old.decode()).encode()
        if old != new:
            planned.append((path, profile, old, new, path.stat().st_mode & 0o777))
    backup = HERE / 'connection-repair' / ('ownership-before-' + uuid.uuid4().hex)
    backup.mkdir(mode=0o700)
    rows = []
    completed = []
    try:
        for path, profile, old, new, mode in planned:
            saved = backup / (str(len(rows)) + '-' + path.name)
            atomic_write(saved, old, 0o600)
            rows.append({'path':str(path), 'backup':str(saved)})
            atomic_write(path, new, mode)
            completed.append((path, profile, old, mode))
            if profile:
                target = f"gui/{os.getuid()}/{profile['Label']}"
                result = subprocess.run(['/bin/launchctl','kickstart','-k',target],capture_output=True,timeout=20)
                if result.returncode:
                    raise RuntimeError('Worker restart failed: ' + result.stderr.decode()[:500])
    except BaseException:
        for path, profile, old, mode in reversed(completed):
            atomic_write(path, old, mode)
            if profile:
                target = f"gui/{os.getuid()}/{profile['Label']}"
                subprocess.run(['/bin/launchctl','kickstart','-k',target],capture_output=True,timeout=20,check=False)
        raise
    atomic_write(backup/'index.json',json.dumps(rows,indent=2).encode())
    print(json.dumps({'changed_files':len(planned),'backup':str(backup)},indent=2))


if __name__ == '__main__':
    main()
