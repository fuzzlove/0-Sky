#!/usr/bin/env python3
"""Read-only Frida provenance and transport probe for one paired SRD.

Process enumeration is deliberately the limit of this probe. Attach, spawn,
and RPC require the designated 0-Sky test app and remain separate UAT cases.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import time
import uuid

from repair_device_connection import profiles, usb_identity, worker_namespace


HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "srdsh-work/components/zero-sky/kit/frida/17.18.0-ios/0sky-frida-manifest.json"
HOST_FRIDA = Path.home() / "Library/Application Support/0-Sky/tools/frida-current/bin/python"
REQUIRED_CHECKS = ("usb_identity", "artifact_hash", "server_process",
                   "localhost_listener", "host_version", "process_enumeration")


def private_receipt(instance: str, udid: str) -> tuple[Path, str] | None:
    selected = profiles(instance_name=instance)
    if udid not in selected:
        return None
    env = selected[udid][1]["EnvironmentVariables"]
    if env.get("CRYPSTORE_DEVICE_UDID") != udid:
        raise RuntimeError("paired profile identity changed")
    directory = Path(env["CRYPSTORE_INSTANCE_DIR"]) / "uat"
    if directory.is_symlink():
        raise RuntimeError("paired UAT directory is a symbolic link")
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077):
        raise RuntimeError("paired UAT directory is not private")
    receipt = directory / "frida.json"
    if receipt.is_symlink():
        raise RuntimeError("paired Frida receipt is a symbolic link")
    fingerprint = env.get("CRYPSTORE_HOST_KEY_FINGERPRINT")
    if not isinstance(fingerprint, str) or not fingerprint.startswith("SHA256:"):
        raise RuntimeError("paired host key fingerprint unavailable")
    return receipt, fingerprint


def write_private_receipt(receipt: Path, fingerprint: str, udid: str,
                          result: dict) -> None:
    if result.get("result") != "PASS":
        raise ValueError("only a passing probe can create a receipt")
    binding = {"schema": 1, "result": "PASS",
               "device_digest": hashlib.sha256(udid.encode()).hexdigest(),
               "host_key_fingerprint": fingerprint,
               "timestamp": int(result["timestamp"]),
               "host_version": result["handshake"]["host_version"],
               "device_version": "17.18.0",
               "transport": "exact_usb_iproxy",
               "checks": {name: True for name in REQUIRED_CHECKS},
               "scope": "read_only_process_enumeration"}
    temporary = receipt.with_name(".frida-" + uuid.uuid4().hex + ".tmp")
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


def remote_probe(worker: dict, expected: dict[str, str]) -> dict:
    code = """import glob,hashlib,json,os,shutil,socket,subprocess
expected=json.loads(%r)
files={}
for name,sha in expected.items():
 try:
  h=hashlib.sha256()
  with open(name,'rb') as stream:
   for chunk in iter(lambda:stream.read(1048576),b''):h.update(chunk)
  files[name]={'present':True,'sha256_match':h.hexdigest()==sha,'executable':os.access(name,os.X_OK)}
 except OSError as error:files[name]={'present':False,'error':type(error).__name__}
try:
 sock=socket.create_connection(('127.0.0.1',27042),timeout=2);sock.close();listener=True
except OSError:listener=False
try:
 rows=subprocess.run(['/bin/ps','-A','-o','comm='],capture_output=True,text=True,timeout=5,check=True).stdout.splitlines()
 process=any(row.strip().endswith('/frida-server') for row in rows)
except (OSError,subprocess.SubprocessError):process=False
trusted=[]
for path in glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/codes.openai.research.ellekitloader.*/usr/sbin/frida-server'):
 try:
  with open(path,'rb') as stream:trusted.append(hashlib.sha256(stream.read()).hexdigest()==expected['/var/jb/usr/sbin/frida-server'])
 except OSError:trusted.append(False)
print(json.dumps({'files':files,'listener':listener,'process':process,
                  'trusted_cryptex_payloads':len(trusted),
                  'trusted_cryptex_hash_match':any(trusted),
                  'launchctl':shutil.which('launchctl')}))
""" % json.dumps(expected, sort_keys=True)
    result = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(code),
                           timeout=25, check=False)
    if result.returncode:
        raise RuntimeError("PINNED_SSH_PROBE_FAILED")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("INVALID_DEVICE_RESPONSE")
    return value


def frida_handshake(udid: str) -> dict:
    iproxy = shutil.which("iproxy")
    if not iproxy or not HOST_FRIDA.is_file():
        return {"result": "BLOCKED", "reason": "HOST_FRIDA_OR_IPROXY_MISSING"}
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    route = subprocess.Popen([iproxy, "-s", "127.0.0.1", "-u", udid,
                              f"{port}:27042"], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    try:
        for _ in range(30):
            if route.poll() is not None:
                return {"result": "FAIL", "reason": "EXACT_USB_ROUTE_FAILED"}
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            return {"result": "FAIL", "reason": "EXACT_USB_ROUTE_TIMEOUT"}
        code = ("import frida,json,sys; "
                "d=frida.get_device_manager().add_remote_device('127.0.0.1:'+sys.argv[1]); "
                "p=d.enumerate_processes(); "
                "print(json.dumps({'host_version':frida.__version__, "
                "'process_count':len(p), "
                "'test_app_seen':any('crypstore' in x.name.lower() or "
                "'0-sky' in x.name.lower() for x in p)}))")
        result = subprocess.run([str(HOST_FRIDA), "-c", code, str(port)],
                                capture_output=True, text=True, timeout=15,
                                check=False)
        if result.returncode:
            return {"result": "FAIL", "reason": "FRIDA_HANDSHAKE_FAILED"}
        value = json.loads(result.stdout)
        if not isinstance(value, dict) or not isinstance(value.get("process_count"), int):
            return {"result": "FAIL", "reason": "INVALID_FRIDA_RESPONSE"}
        return {"result": "PASS", "host_version": value.get("host_version"),
                "process_count": value["process_count"],
                "test_app_seen": value.get("test_app_seen") is True,
                "transport": "exact_usb_iproxy"}
    finally:
        route.terminate()
        try:
            route.wait(timeout=3)
        except subprocess.TimeoutExpired:
            route.kill()
            route.wait(timeout=3)


def run(instance: str, udid: str) -> dict:
    if (not isinstance(udid, str) or not 8 <= len(udid) <= 40 or
            not all(char.isascii() and (char.isalnum() or char == "-") for char in udid)):
        raise ValueError("INVALID_UDID")
    report = {"device_suffix": udid[-8:], "timestamp": int(time.time()),
              "result": "BLOCKED", "scope": "read_only_process_enumeration",
              "full_frida_uat": "UNVERIFIED"}
    selected = profiles(instance_name=instance)
    if udid not in selected:
        report["reason"] = "PAIRED_PROFILE_MISSING"
        return report
    try:
        identity = asyncio.run(usb_identity(udid))
    except RuntimeError as error:
        report["reason"] = "USB_NOT_CONNECTED" if "USB_NOT_CONNECTED" in str(error) else "USB_IDENTITY_FAILED"
        return report
    report.update(ios=identity.get("version"), build=identity.get("build"))
    try:
        manifest = json.loads(MANIFEST.read_text())
        expected = manifest["files"]
        if not isinstance(expected, dict) or not expected or not all(
                isinstance(name, str) and name.startswith("/var/jb/") and
                ".." not in Path(name).parts and
                isinstance(sha, str) and len(sha) == 64
                for name, sha in expected.items()):
            raise ValueError("invalid Frida manifest")
    except (OSError, ValueError, KeyError, TypeError):
        report["reason"] = "FRIDA_MANIFEST_INVALID"
        return report
    worker = worker_namespace(selected[udid][1])
    try:
        device = remote_probe(worker, expected)
    except (RuntimeError, ValueError, KeyError) as error:
        report["reason"] = type(error).__name__
        return report
    report["device"] = device
    files = device.get("files")
    if not isinstance(files, dict) or set(files) != set(expected) or not all(
            isinstance(item, dict) and item.get("sha256_match") is True
            for item in files.values()):
        report.update(result="FAIL", reason="FRIDA_ARTIFACT_MISMATCH")
        return report
    if not device.get("process") or not device.get("listener"):
        reason = ("FRIDA_TRUST_CRYPTEX_MISSING" if not device.get("trusted_cryptex_hash_match")
                  else "FRIDA_SERVER_NOT_RUNNING")
        report.update(result="DEGRADED", reason=reason)
        return report
    try:
        handshake = frida_handshake(udid)
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        handshake = {"result": "FAIL", "reason": type(error).__name__}
    report["handshake"] = handshake
    if handshake["result"] == "PASS" and handshake.get("host_version") == manifest["version"]:
        report.update(result="PASS", reason="PROVENANCE_AND_ENUMERATION_PASS")
    else:
        report.update(result="DEGRADED", reason="FRIDA_HANDSHAKE_OR_VERSION_UNVERIFIED")
    return report


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: paired_frida_probe.py INSTANCE EXACT_UDID")
    receipt_binding = private_receipt(sys.argv[1], sys.argv[2])
    if receipt_binding:
        receipt_binding[0].unlink(missing_ok=True)
    result = run(sys.argv[1], sys.argv[2])
    destination = HERE / "0sky-uat" / result["device_suffix"].lower() / "paired-frida-probe.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise RuntimeError("refusing symbolic-link probe report")
    payload = json.dumps(result, sort_keys=True, indent=2) + "\n"
    history = destination.parent / "frida-probe-history"
    history.mkdir(exist_ok=True)
    unique = str(result["timestamp"]) + "-" + uuid.uuid4().hex[:8]
    with (history / (unique + ".json")).open("x") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    temporary = destination.with_name(".paired-frida-probe-" + unique)
    with temporary.open("x") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    if result["result"] == "PASS" and receipt_binding:
        write_private_receipt(receipt_binding[0], receipt_binding[1],
                              sys.argv[2], result)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
