#!/usr/bin/env python3
"""Frida UAT scoped to the installed 0-Sky Security Test app."""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid

from paired_frida_probe import HOST_FRIDA, run as provenance_probe
from repair_device_connection import profiles, usb_identity
from security_test_fixture_install import (BUNDLE_ID, cryptex_versions, query_app)


HERE = Path(__file__).resolve().parent
HOST_CODE = r'''
import frida,json,sys,time
port=sys.argv[1]
bundle='com.liquidsky.SecurityTest'
result={'result':'FAIL','stage':'CONNECT','checks':{}}
device=None
pid=None
sessions=[]
try:
 device=frida.get_device_manager().add_remote_device('127.0.0.1:'+port)
 result['checks']['host_version']=frida.__version__=='17.18.0'
 apps=device.enumerate_applications()
 result['checks']['fixture_enumerated']=any(a.identifier==bundle for a in apps)
 if not all(result['checks'].values()): raise RuntimeError('FIXTURE_OR_VERSION_MISSING')
 result['stage']='SPAWN'
 pid=device.spawn([bundle])
 result['checks']['spawn']=isinstance(pid,int) and pid>0
 result['stage']='ATTACH'
 session=device.attach(pid)
 sessions.append(session)
 script=session.create_script("""rpc.exports = {
 probe: function () {
  if (typeof ObjC === 'undefined' || !ObjC.available)
   return {objc: false, echo: null, sum: null};
  var cls = ObjC.classes.ZSSecurityProbe;
  if (!cls) return {objc: false, echo: null, sum: null};
  var obj = cls.alloc().init();
  var echo = obj.echo_(ObjC.classes.NSString.stringWithString_('frida'));
  var sum = obj.add_to_(ObjC.classes.NSNumber.numberWithInt_(2),
                        ObjC.classes.NSNumber.numberWithInt_(3));
  return {objc: true, echo: String(echo), sum: Number(sum.intValue())};
 }
};""")
 script.load()
 device.resume(pid)
 time.sleep(1)
 result['checks']['attach']=True
 result['stage']='RPC'
 value=script.exports_sync.probe()
 result['checks']['objc_method_rpc']=(value.get('objc') is True and
   value.get('echo')=='0sky-test:frida' and value.get('sum')==5)
 result['observed_rpc']=value
 result['stage']='DETACH'
 session.detach()
 sessions.clear()
 result['checks']['detach']=True
 result['stage']='REATTACH'
 session=device.attach(pid)
 sessions.append(session)
 again=session.create_script('rpc.exports={ping:function(){return Process.id;}};')
 again.load()
 result['checks']['reattach_rpc']=again.exports_sync.ping()==pid
 session.detach()
 sessions.clear()
 result['result']='PASS' if all(result['checks'].values()) else 'DEGRADED'
 result['stage']='COMPLETE'
except Exception as error:
 result['error_code']=(str(error) if isinstance(error,RuntimeError) and
  str(error) in ('FIXTURE_OR_VERSION_MISSING',) else type(error).__name__)
finally:
 for session in sessions:
  try: session.detach()
  except Exception: pass
 if device is not None and pid is not None:
  try: device.kill(pid); result['checks']['cleanup']=True
  except Exception: result['checks']['cleanup']=False
 print(json.dumps(result,sort_keys=True))
'''


def exact_route(udid: str, port: int):
    iproxy = shutil.which("iproxy")
    if not iproxy:
        raise RuntimeError("IPROXY_UNAVAILABLE")
    return subprocess.Popen([iproxy, "-s", "127.0.0.1", "-u", udid,
                             f"{port}:27042"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def run(instance: str, udid: str) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected or asyncio.run(usb_identity(udid))["udid"] != udid:
        raise RuntimeError("EXACT_USB_PROFILE_MISMATCH")
    app = query_app(udid)
    versions = asyncio.run(cryptex_versions(udid))
    if (app.get("CFBundleIdentifier") != BUNDLE_ID or
            app.get("CFBundleShortVersionString") != "1.0.0" or len(versions) != 1):
        raise RuntimeError("CONTROLLED_FIXTURE_NOT_REGISTERED_AND_TRUSTED")
    provenance = provenance_probe(instance, udid)
    if provenance.get("result") != "PASS":
        return {"device_suffix": udid[-8:], "result": "BLOCKED",
                "stage": "FRIDA_PROVENANCE", "reason": provenance.get("reason")}
    if not HOST_FRIDA.is_file():
        raise RuntimeError("PINNED_HOST_FRIDA_UNAVAILABLE")
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    route = exact_route(udid, port)
    try:
        for _ in range(30):
            if route.poll() is not None:
                raise RuntimeError("EXACT_USB_ROUTE_FAILED")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("EXACT_USB_ROUTE_TIMEOUT")
        process = subprocess.run([str(HOST_FRIDA), "-c", HOST_CODE, str(port)],
                                 capture_output=True, text=True, timeout=75,
                                 check=False)
        if process.returncode or not process.stdout.strip():
            return {"device_suffix": udid[-8:], "result": "FAIL",
                    "stage": "HOST_FRIDA", "error_code": "FRIDA_HOST_PROCESS_FAILED"}
        observed = json.loads(process.stdout.splitlines()[-1])
        observed["device_suffix"] = udid[-8:]
        observed["scope"] = "com.liquidsky.SecurityTest_only"
        return observed
    finally:
        route.terminate()
        try:
            route.wait(timeout=3)
        except subprocess.TimeoutExpired:
            route.kill()
            route.wait(timeout=3)


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: controlled_frida_uat.py INSTANCE EXACT_UDID")
    result = run(sys.argv[1], sys.argv[2])
    directory = HERE / "0sky-uat" / result["device_suffix"].lower()
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / "frida-controlled-uat.json"
    if destination.is_symlink():
        raise RuntimeError("refusing symbolic-link UAT report")
    temporary = destination.with_name("." + destination.name + "-" + uuid.uuid4().hex)
    with temporary.open("x") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
