#!/usr/bin/env python3
"""Bounded authorized-key SSH and file round-trip UAT for one paired SRD."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import time
import uuid

from repair_device_connection import profiles, usb_identity, worker_namespace


HERE = Path(__file__).resolve().parent
ROOT = Path("/var/jb/var")


def remote(worker: dict, code: str, *, timeout: int = 25) -> dict:
    result = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(code),
                           timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError("paired SSH command failed with exit " + str(result.returncode) +
                           ": " + result.stderr.decode("utf-8", "replace")[:160])
    try:
        value = json.loads(result.stdout)
    except ValueError as error:
        raise RuntimeError("paired SSH returned invalid JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("paired SSH returned an invalid result")
    return value


def run(instance: str, udid: str) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("exact paired profile and USB identity differ")
    worker = worker_namespace(selected[udid][1])
    receipt_dir = Path(worker["INSTANCE"]) / "uat"
    if receipt_dir.is_symlink():
        raise RuntimeError("paired worker UAT directory is a symbolic link")
    receipt_dir.mkdir(mode=0o700, exist_ok=True)
    directory_info = receipt_dir.stat()
    if (not stat.S_ISDIR(directory_info.st_mode) or
            directory_info.st_uid != os.getuid() or directory_info.st_mode & 0o077):
        raise RuntimeError("paired worker UAT directory is not private")
    receipt = receipt_dir / "ssh.json"
    if receipt.is_symlink():
        raise RuntimeError("paired worker UAT receipt is a symbolic link")
    receipt.unlink(missing_ok=True)  # A failed new run must revoke an older PASS.
    base = worker["SSH_BASE"]
    required = {"BatchMode=yes", "StrictHostKeyChecking=yes", "PasswordAuthentication=no",
                "KbdInteractiveAuthentication=no", "IdentitiesOnly=yes"}
    if not required.issubset(set(base)) or "-i" not in base:
        raise RuntimeError("paired worker does not enforce pinned public-key SSH")
    environment = selected[udid][1].get("EnvironmentVariables", {})
    raw_remote_port = environment.get("CRYPSTORE_DEVICE_REMOTE_PORT")
    if (not isinstance(raw_remote_port, str) or not raw_remote_port.isdecimal() or
            not 1 <= int(raw_remote_port) <= 65535):
        raise RuntimeError("paired worker remote SSH port is invalid")
    expected_remote_port = int(raw_remote_port)
    started = time.monotonic()
    preflight = remote(worker, """import json,os,shlex,socket,subprocess
expected_port=%d
rows=subprocess.run(['/bin/ps','-axo','command='],capture_output=True,text=True,
                    timeout=10,check=True).stdout.splitlines()
servers=[]
for row in rows:
    try: args=shlex.split(row)
    except ValueError: continue
    if not args or os.path.basename(args[0]) not in ('dropbear','sshd'): continue
    port=None
    for index,arg in enumerate(args):
        if arg=='-p' and index+1<len(args): candidate=args[index+1]
        elif arg.startswith('-p') and len(arg)>2: candidate=arg[2:]
        else: continue
        if candidate.isdecimal() and 1<=int(candidate)<=65535: port=int(candidate)
    if port==expected_port: servers.append(os.path.basename(args[0]))
sock=socket.socket(); sock.settimeout(2)
try: listener=sock.connect_ex(('127.0.0.1',expected_port))==0
finally: sock.close()
print(json.dumps({'euid':os.geteuid(),'server_process':bool(servers),
                  'listener_port':expected_port,'localhost_listener':listener}))
""" % expected_remote_port)
    if preflight.get("euid") != 0:
        raise RuntimeError("paired SSH did not open a root shell")
    token = uuid.uuid4().hex
    path = ROOT / (".0sky-ssh-uat-" + token)
    contents = ("0-Sky paired SSH file test " + token + "\n").encode()
    expected = hashlib.sha256(contents).hexdigest()
    write = """import base64,hashlib,json,os,pathlib
p=pathlib.Path(%r)
if p.parent!=pathlib.Path('/var/jb/var') or p.is_symlink(): raise RuntimeError('unsafe test path')
data=base64.b64decode(%r,validate=True)
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'wb') as stream: stream.write(data); stream.flush(); os.fsync(stream.fileno())
print(json.dumps({'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':p.stat().st_mode&0o777}))
""" % (str(path), base64.b64encode(contents).decode())
    read = """import base64,hashlib,json,pathlib
p=pathlib.Path(%r)
if p.is_symlink() or not p.is_file(): raise RuntimeError('test file is absent or unsafe')
data=p.read_bytes()
print(json.dumps({'sha256':hashlib.sha256(data).hexdigest(),
                  'contents':base64.b64encode(data).decode()}))
""" % str(path)
    cleanup = """import json,pathlib
p=pathlib.Path(%r)
if p.is_symlink(): raise RuntimeError('unsafe test file')
p.unlink(missing_ok=True)
print(json.dumps({'removed':not p.exists()}))
""" % str(path)
    primary_error = None
    try:
        written = remote(worker, write)
        observed = remote(worker, read)
        if (written.get("sha256") != expected or written.get("mode") != 0o600 or
                observed.get("sha256") != expected or
                base64.b64decode(observed.get("contents", ""), validate=True) != contents):
            raise RuntimeError("paired SSH file round trip differs")
    except Exception as error:
        primary_error = error
    try:
        removed = remote(worker, cleanup)
        if removed.get("removed") is not True:
            raise RuntimeError("paired SSH test file cleanup failed")
    except Exception as cleanup_error:
        if primary_error is not None:
            raise ExceptionGroup("SSH UAT and cleanup both failed",
                                 [primary_error, cleanup_error])
        raise
    if primary_error is not None:
        raise primary_error
    reconnected = remote(worker, "import json,os; print(json.dumps({'euid':os.geteuid()}))")
    if reconnected.get("euid") != 0:
        raise RuntimeError("paired SSH reconnect failed")
    transport = worker["ssh"].__globals__.get("ACTIVE_SSH_TRANSPORT", "unknown")
    result = {"device": udid[-8:], "result": "PASS" if preflight.get("server_process")
              and preflight.get("localhost_listener") else "DEGRADED",
              "checks": {"usb_identity": True, "pinned_public_key": True,
                         "root_shell": True, "server_process": preflight.get("server_process") is True,
                         "localhost_listener": preflight.get("localhost_listener") is True,
                         "file_round_trip": True, "cleanup": True, "reconnect": True},
              "listener_port": preflight.get("listener_port"),
              "transport": transport, "duration_ms": round((time.monotonic()-started)*1000),
              "evidence": ["exact USB identity and paired profile matched",
                           "strict host-key checking and public-key-only SSH enforced",
                           "temporary file hash and contents matched across sessions"],
              "remediation": None if preflight.get("server_process") and
              preflight.get("localhost_listener") else "Inspect the on-device SSH listener and service"}
    directory = HERE / "0sky-uat" / udid[-8:].lower()
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "paired-ssh-uat.json").write_text(
        json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    if result["result"] == "PASS":
        binding = {"schema": 1, "device_digest": hashlib.sha256(udid.encode()).hexdigest(),
                   "host_key_fingerprint": worker["HOST_KEY_FINGERPRINT"],
                   "timestamp": int(time.time()), "result": "PASS",
                   "checks": result["checks"], "transport": transport}
        if not binding["host_key_fingerprint"]:
            raise RuntimeError("paired host key fingerprint is unavailable")
        temporary = receipt.with_name(".ssh-" + uuid.uuid4().hex + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(binding, stream, sort_keys=True)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, receipt)
        finally:
            temporary.unlink(missing_ok=True)
    return result


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: paired_ssh_uat.py INSTANCE EXACT_UDID")
    print(json.dumps(run(sys.argv[1], sys.argv[2]), sort_keys=True))
