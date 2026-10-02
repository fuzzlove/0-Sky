#!/usr/bin/env python3
"""Transactionally stage the reviewed Control toolkit runtime on one paired SRD."""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
from pathlib import Path
import shlex
import sys
import time
import uuid
import zipfile

from repair_device_connection import profiles, usb_identity, worker_namespace


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / "bridge/DeviceRuntime"
FILES = (
    "trollstorelite-srd-bridge.py",
    "zero_sky_core/ipc.py", "zero_sky_core/runtime.py",
    "zero_sky_core/logging.py",
    "zero_sky_core/research_toolkit.py",
    "zero_sky_core/research_toolkit_device.py",
    "zero_sky_core/research_toolkit_runner.py",
    "zero_sky_core/package_integration.py",
    "zero_sky_core/research_toolkit_manifest.json",
    "zero_sky_core/sensors/recovery.py",
    "zero_sky_core/control_install_policy.py",
    "zero_sky_core/control_install_service.py",
    "zero_sky_core/control_install_transaction.py",
    "zero_sky_core/control_payload.py",
    "zero_sky_compat/__init__.py",
    "zero_sky_compat/__main__.py",
    "zero_sky_compat/adapters.py",
    "zero_sky_compat/analysis.py",
    "zero_sky_compat/discovery.py",
    "zero_sky_compat/engine.py",
    "zero_sky_compat/environment.py",
    "zero_sky_compat/failures.py",
    "zero_sky_compat/intake.py",
    "zero_sky_compat/integration.py",
    "zero_sky_compat/inventory.py",
    "zero_sky_compat/macho.py",
    "zero_sky_compat/model.py",
    "zero_sky_compat/paths.py",
    "zero_sky_compat/probes.py",
    "zero_sky_compat/registry.py",
    "zero_sky_compat/rules.py",
    "zero_sky_compat/transaction.py",
    "zero_sky_compat/validation.py",
)


def payload() -> tuple[bytes, dict[str, str]]:
    memory = io.BytesIO()
    hashes = {}
    with zipfile.ZipFile(memory, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative in FILES:
            source = RUNTIME / relative
            if not source.is_file() or source.is_symlink():
                raise RuntimeError("reviewed runtime source is absent or unsafe: " + relative)
            contents = source.read_bytes()
            hashes[relative] = hashlib.sha256(contents).hexdigest()
            archive.writestr(relative, contents)
    return memory.getvalue(), hashes


def receiver(hashes: dict[str, str], run_id: str) -> str:
    return f'''
import hashlib, io, json, os, pathlib, py_compile, shutil, sys, zipfile
root=pathlib.Path('/var/jb/usr/local/libexec')
expected={repr(hashes)}
run_id={run_id!r}
stage=root/('.toolkit-stage-'+run_id)
backup=root/('.toolkit-backup-'+run_id)
if stage.exists() or backup.exists(): raise RuntimeError('toolkit staging name already exists')
stage.mkdir(mode=0o700)
backup.mkdir(mode=0o700)
previous={{}}
replaced=[]
try:
 archive=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read()))
 names=archive.namelist()
 if len(names)!=len(expected) or set(names)!=set(expected):
  raise RuntimeError('toolkit archive member set differs')
 for info in archive.infolist():
  if info.is_dir() or info.file_size>1048576 or '..' in pathlib.PurePosixPath(info.filename).parts:
   raise RuntimeError('toolkit archive has unsafe member')
  data=archive.read(info)
  if hashlib.sha256(data).hexdigest()!=expected[info.filename]:
   raise RuntimeError('toolkit source digest mismatch')
  target=stage/info.filename
  target.parent.mkdir(parents=True,exist_ok=True)
  target.write_bytes(data)
  target.chmod(0o644)
  if target.suffix=='.py': py_compile.compile(str(target),doraise=True)
 for relative in expected:
  live=root/relative
  if live.is_symlink(): raise RuntimeError('existing toolkit target is a symbolic link')
  previous[relative]=live.exists()
  if live.exists():
   old=backup/relative
   old.parent.mkdir(parents=True,exist_ok=True)
   shutil.copy2(live,old)
 (backup/'previous.json').write_text(json.dumps(previous,sort_keys=True))
 for relative in expected:
  live=root/relative
  live.parent.mkdir(parents=True,exist_ok=True)
  os.replace(stage/relative,live)
  replaced.append(relative)
 print(json.dumps({{'backup':str(backup),'files':len(expected)}}))
except Exception:
 for relative in reversed(replaced):
  live=root/relative
  if previous.get(relative): shutil.copy2(backup/relative,live)
  elif live.exists(): live.unlink()
 raise
finally:
 shutil.rmtree(stage,ignore_errors=True)
'''


RESTART = r'''
import json, os, signal, subprocess, time
expected='/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py'
deadline=time.monotonic()+8
while True:
 ps=subprocess.run(['/bin/ps','-axo','pid=,command='],capture_output=True,text=True,check=True)
 matches=[]
 for line in ps.stdout.splitlines():
  parts=line.strip().split(None,1)
  if len(parts)==2 and parts[1].strip()=='/var/jb/usr/bin/python3 '+expected:
   matches.append(int(parts[0]))
 if len(matches)==1: break
 if time.monotonic()>=deadline: raise RuntimeError('expected one active device Bridge process')
 time.sleep(0.25)
os.kill(matches[0],signal.SIGTERM)
print(json.dumps({'signaled':True}))
'''


def rollback_code(backup: str) -> str:
    return f'''
import json, pathlib, shutil
root=pathlib.Path('/var/jb/usr/local/libexec')
backup=pathlib.Path({backup!r})
if backup.parent!=root or not backup.name.startswith('.toolkit-backup-'):
 raise RuntimeError('invalid toolkit backup path')
previous=json.loads((backup/'previous.json').read_text())
for relative,existed in previous.items():
 if relative not in {repr(FILES)}: raise RuntimeError('invalid backup member')
 live=root/relative
 if existed: shutil.copy2(backup/relative,live)
 elif live.exists(): live.unlink()
print(json.dumps({{'restored':len(previous)}}))
'''


def remote_python(worker: dict, code: str, *, data: bytes | None = None,
                  timeout: int = 90) -> dict:
    command = "/var/jb/usr/bin/python3 -c " + shlex.quote(code)
    result = worker["ssh"](command, input_data=data, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("paired SRD operation failed (exit " + str(result.returncode) + "): " +
                           result.stderr.decode("utf-8", "replace")[:300])
    return json.loads(result.stdout)


HEALTH = r'''
import json,time,urllib.error,urllib.request
from pathlib import Path
token=Path('/var/jb/etc/trollstorelite-srd-bridge.token').read_text().strip()
payload={'protocolVersion':1,'requestId':'toolkit-deployment-check',
 'timestamp':time.time(),'operation':'getResearchToolkit','parameters':{}}
request=urllib.request.Request('http://127.0.0.1:48654/v1/core',
 data=json.dumps(payload).encode(),headers={'X-TrollStore-Bridge-Token':token,
 'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=8) as response:
 result=json.load(response)
snapshot=result.get('result') or {}
print(json.dumps({'success':result.get('success') is True,
                  'components':len(snapshot.get('components',[])),
                  'os':snapshot.get('environment',{}).get('ios_version')}))
'''


def wait_health(worker: dict, timeout: float = 35) -> dict:
    deadline = time.monotonic() + timeout
    error = "Bridge did not restart with toolkit support"
    while time.monotonic() < deadline:
        try:
            value = remote_python(worker, HEALTH, timeout=15)
            if value.get("success") is True and value.get("components", 0) >= 30:
                return value
            error = "Bridge toolkit snapshot is incomplete"
        except (OSError, ValueError, RuntimeError) as failure:
            error = type(failure).__name__ + ": " + str(failure)[:120]
        time.sleep(2)
    raise RuntimeError(error)


def deploy(instance: str, udid: str) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected:
        raise RuntimeError("exact paired worker profile does not match USB device")
    usb = asyncio.run(usb_identity(udid))
    if usb["udid"] != udid:
        raise RuntimeError("exact USB identity changed")
    worker = worker_namespace(selected[udid][1])
    archive, hashes = payload()
    run_id = uuid.uuid4().hex
    staged = remote_python(worker, receiver(hashes, run_id), data=archive, timeout=120)
    backup = staged["backup"]
    try:
        remote_python(worker, RESTART, timeout=20)
        health = wait_health(worker)
    except Exception as failure:
        remote_python(worker, rollback_code(backup), timeout=30)
        try:
            remote_python(worker, RESTART, timeout=20)
        except Exception as restart_error:
            raise RuntimeError("toolkit files were restored, but Bridge restart failed: " +
                               str(restart_error)[:160]) from failure
        raise
    return {"device": udid[-8:], "backup": backup, "files": staged["files"],
            "health": health}


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: deploy_toolkit_runtime.py INSTANCE EXACT_UDID")
    print(json.dumps(deploy(sys.argv[1], sys.argv[2]), sort_keys=True))
