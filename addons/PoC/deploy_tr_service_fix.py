"""Make TrollRecorder's verified launchd service part of SRD installs."""
import json
import os
import subprocess
import uuid
from pathlib import Path

from repair_device_connection import HERE, atomic_write, profiles
from trollrecorder_service_program import PROGRAM


def patch_source(source: str) -> str:
    signature = 'def ensure_trollrecorder_srd_service('
    definition_point = 'def register_and_link(bundle_id: str, executable: str, app_name: str, mount: str,'
    fragment = '''def ensure_trollrecorder_srd_service(bundle_id: str, registered_app: str,
                                    cryptex_app: str) -> None:
    """Install or refresh the verified vendor daemon after MCM registration."""
    if bundle_id != 'wiki.qaq.trapp':
        return
    program = ''' + repr(PROGRAM) + '''
    command = (
        '/var/jb/usr/bin/python3 -c ' + shlex.quote(program) + ' '
        + ' '.join(shlex.quote(value) for value in
                   (bundle_id, registered_app, cryptex_app))
    )
    result = ssh(command, timeout=100)
    report = json.loads(result.stdout)
    job = report.get('job', {})
    if not (job.get('pid') and
            job.get('program') == str(pathlib.Path(registered_app) / 'TRCallMonitor')):
        raise RuntimeError('TrollRecorder launchd service did not stay running')
    log('verified TrollRecorder launchd service pid ' + str(job['pid']))


'''
    if signature not in source:
        if source.count(definition_point) != 1:
            raise RuntimeError('Unexpected registration definition')
        source = source.replace(definition_point, fragment + definition_point)
    call_point = '    mark_trollstore_owned_mcm(bundle_id, registered_app, cryptex_app, executable)\n'
    call = '    ensure_trollrecorder_srd_service(bundle_id, registered_app, cryptex_app)\n'
    if call not in source:
        if source.count(call_point) != 1:
            raise RuntimeError('Unexpected MCM ownership boundary')
        source = source.replace(call_point, call_point + call)
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
    backup = HERE / 'connection-repair' / ('service-before-' + uuid.uuid4().hex)
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
