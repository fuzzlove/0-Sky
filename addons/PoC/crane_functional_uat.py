#!/usr/bin/env python3
"""Verify paid Crane container redirection in the controlled 0-Sky fixture.

Crane normally receives its selected container through the spawn environment.
The SRD adapter writes that state into the fixture's private data container;
the converted fixture consumes it before loading Crane. This test creates a
temporary container, verifies real I/O isolation, restores the original state,
validates the rollback launch, and removes all temporary evidence.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import pathlib
import re
import subprocess
import sys
import time
import uuid

from repair_device_connection import atomic_write, profiles, usb_identity, worker_namespace


TRUSTED_LAUNCHCTL_SHA256 = (
    "a2d095b681cd4bf1ac819a7052b5b376516ed663bd989edc60d25297fa1e9bbc"
)
LAUNCHCTL_PATH = re.compile(
    r"^/private/var/run/com\.apple\.security\.cryptexd/mnt/"
    r"com\.liquidsky\.launch-helper\.recovery-[A-Za-z0-9._-]+/usr/bin/launchctl-srd$"
)


REMOTE_TEST = r'''
import ctypes
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
import uuid

BUNDLE_ID = "com.liquidsky.SecurityTest"
FIXTURE_HOME = pathlib.Path("__FIXTURE_HOME__")
LIBCRANE = pathlib.Path("/var/jb/usr/lib/libcrane.dylib")
MARKER_NAME = "0sky-crane-uat.txt"
RTLD_GLOBAL = 0x8
RUNTIME_STATE = pathlib.Path("/var/jb/var/lib/srd-runtime")
DEFERRED_MARKER_CLEANUP = []


def stage(value):
    print("CRANE_UAT_STAGE=" + value, file=sys.stderr, flush=True)


stage("START")
os.setegid(501)
os.seteuid(501)
ctypes.CDLL("/System/Library/Frameworks/Foundation.framework/Foundation", mode=RTLD_GLOBAL)
ctypes.CDLL(str(LIBCRANE), mode=RTLD_GLOBAL)
stage("LIBCRANE_LOADED")
objc = ctypes.CDLL("/usr/lib/libobjc.A.dylib")
objc.objc_getClass.argtypes = [ctypes.c_char_p]
objc.objc_getClass.restype = ctypes.c_void_p
objc.sel_registerName.argtypes = [ctypes.c_char_p]
objc.sel_registerName.restype = ctypes.c_void_p
message = objc.objc_msgSend


def cls(name):
    return objc.objc_getClass(name.encode())


def selector(name):
    return objc.sel_registerName(name.encode())


def send(result_type, receiver, name, *arguments, argument_types=()):
    message.restype = result_type
    message.argtypes = [ctypes.c_void_p, ctypes.c_void_p, *argument_types]
    return message(receiver, selector(name), *arguments)


def ns(value):
    return send(ctypes.c_void_p, cls("NSString"), "stringWithUTF8String:",
                value.encode(), argument_types=(ctypes.c_char_p,))


def string(value):
    if not value:
        return None
    data = send(ctypes.c_char_p, value, "UTF8String")
    return data.decode("utf-8", "replace") if data else None


def contains(array, value):
    return bool(send(ctypes.c_bool, array, "containsObject:", value,
                     argument_types=(ctypes.c_void_p,)))


def array_values(array):
    count = send(ctypes.c_ulong, array, "count") if array else 0
    return [send(ctypes.c_void_p, array, "objectAtIndex:", index,
                 argument_types=(ctypes.c_ulong,)) for index in range(count)]


def fixture_pid():
    result = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True,
                            text=True, timeout=10, check=True)
    for line in result.stdout.splitlines():
        if "/ZeroSkySecurityTest.app/ZeroSkySecurityTest" not in line:
            continue
        fields = line.strip().split(None, 1)
        if fields and fields[0].isdigit():
            return int(fields[0])
    return None


def stop_fixture():
    pid = fixture_pid()
    if not pid:
        return None
    try:
        os.kill(pid, 15)
    except ProcessLookupError:
        return pid
    for _ in range(40):
        if fixture_pid() != pid:
            break
        time.sleep(0.1)
    return pid


def runtime_safe_mode(action):
    request_id = "crane-uat-" + uuid.uuid4().hex
    request_path = RUNTIME_STATE / "safe-mode.request.json"
    result_path = RUNTIME_STATE / "safe-mode.result.json"
    payload = {
        "schema": 1,
        "request_id": request_id,
        "action": action,
        "process": BUNDLE_ID,
        "packages": [],
    }
    os.seteuid(0)
    os.setegid(0)
    try:
        if request_path.exists():
            raise RuntimeError("another runtime recovery action is pending")
        temporary = request_path.with_name(request_path.name + "." + request_id)
        temporary.write_text(json.dumps(payload, sort_keys=True) + "\n")
        temporary.chmod(0o600)
        os.replace(temporary, request_path)
    finally:
        os.setegid(501)
        os.seteuid(501)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        os.seteuid(0)
        os.setegid(0)
        try:
            try:
                result = json.loads(result_path.read_text())
            except (OSError, ValueError):
                result = None
        finally:
            os.setegid(501)
            os.seteuid(501)
        if isinstance(result, dict) and result.get("request_id") == request_id:
            if not result.get("success"):
                raise RuntimeError("runtime safe-mode request failed: " + repr(result))
            return result
        time.sleep(0.2)
    raise RuntimeError("runtime safe-mode request timed out")


def write_handoff(container):
    path = FIXTURE_HOME / "Library/0Sky/Crane/active-container"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not container or container == "DEFAULT":
        path.unlink(missing_ok=True)
        return path
    path.write_text(container + "\n")
    path.chmod(0o600)
    return path


def validated_marker(path):
    path = pathlib.Path(path)
    try:
        path.relative_to(FIXTURE_HOME)
    except ValueError as error:
        raise RuntimeError("refused marker cleanup outside the controlled fixture") from error
    if path.name != MARKER_NAME or path.is_symlink():
        raise RuntimeError("refused unexpected Crane UAT marker cleanup")
    return path


def assert_marker_absent(path):
    path = validated_marker(path)
    if path.exists():
        raise RuntimeError("stale Crane UAT marker requires paired-worker cleanup")


def defer_marker_cleanup(path):
    path = validated_marker(path)
    if path.exists():
        DEFERRED_MARKER_CLEANUP.append(str(path))


def parse_marker(path, token):
    if not path.is_file():
        return None
    value = path.read_text(errors="replace")
    prefix = token + "|hooks="
    if not value.startswith(prefix):
        raise RuntimeError("unexpected marker content: " + repr(value))
    try:
        hooks = int(value[len(prefix):])
    except ValueError as error:
        raise RuntimeError("invalid marker hook count: " + repr(value)) from error
    return {"path": str(path), "value": value, "hooks": hooks}


def launch_url(token, expected_marker):
    old_pid = stop_fixture()
    assert_marker_absent(expected_marker)
    opened = subprocess.run(
        ["/var/jb/usr/bin/uiopen", "--url", "zeroskytest://write/" + token],
        capture_output=True, text=True, timeout=20)
    if opened.returncode:
        raise RuntimeError("fixture URL launch failed: " + opened.stderr[-300:])
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        pid = fixture_pid()
        marker = parse_marker(expected_marker, token)
        if pid and marker:
            time.sleep(0.5)
            if fixture_pid() == pid:
                return {"old_pid": old_pid, "pid": pid, "marker": marker}
        time.sleep(0.2)
    raise RuntimeError("fixture did not remain alive and write the expected marker")


def container_home(manager, application, identifier):
    value = ns(identifier)
    paths = send(ctypes.c_void_p, manager,
        "pathsAssociatedToContainerWithIdentifier:ofApplicationWithIdentifier:",
        value, application, argument_types=(ctypes.c_void_p, ctypes.c_void_p))
    home = send(ctypes.c_void_p, paths, "objectForKey:", application,
        argument_types=(ctypes.c_void_p,)) if paths else None
    return string(home)


manager = send(ctypes.c_void_p, cls("CraneManager"), "sharedManager")
if not manager:
    raise RuntimeError("CraneManager sharedManager is unavailable")
stage("MANAGER_READY")
application = ns(BUNDLE_ID)
stage("HELPER_PROBE_START")
def helper_timeout(_signum, _frame):
    raise TimeoutError("Crane helper connection probe timed out")
signal.signal(signal.SIGALRM, helper_timeout)
signal.alarm(15)
try:
    helper_available = send(ctypes.c_bool, manager, "cranehelperdConnectionWorks")
finally:
    signal.alarm(0)
if not helper_available:
    raise RuntimeError("Crane helper connection is unavailable")
stage("HELPER_PROBE_PASS")
if not send(ctypes.c_bool, manager, "isApplicationSupportedByCrane:", application,
            argument_types=(ctypes.c_void_p,)):
    raise RuntimeError("controlled fixture is not supported by Crane")
stage("APPLICATION_SUPPORTED")

original_object = send(ctypes.c_void_p, manager,
    "activeContainerIdentifierForApplicationWithIdentifier:", application,
    argument_types=(ctypes.c_void_p,))
original = string(original_object) or "DEFAULT"
original_settings = send(ctypes.c_void_p, manager,
    "applicationSettingsForApplicationWithIdentifier:", application,
    argument_types=(ctypes.c_void_p,))
original_settings = send(ctypes.c_void_p, original_settings, "copy") if original_settings else None
original_home = container_home(manager, application, original) or str(FIXTURE_HOME)
stale_containers_removed = []
existing_identifiers = send(ctypes.c_void_p, manager,
    "containerIdentifiersOfApplicationWithIdentifier:", application,
    argument_types=(ctypes.c_void_p,))
for identifier_object in array_values(existing_identifiers):
    identifier = string(identifier_object)
    if not identifier or identifier == original:
        continue
    display_object = send(ctypes.c_void_p, manager,
        "displayNameForContainerWithIdentifier:ofApplicationWithIdentifier:shouldUseShortVersion:",
        identifier_object, application, False,
        argument_types=(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool))
    display_name = string(display_object) or ""
    if not display_name.startswith("0-Sky UAT "):
        continue
    send(None, manager,
        "deleteContainerWithIdentifier:forApplicationWithIdentifier:",
        identifier_object, application,
        argument_types=(ctypes.c_void_p, ctypes.c_void_p))
    stale_containers_removed.append(identifier)
temporary_name = "0-Sky UAT " + uuid.uuid4().hex[:8]
temporary = None
selected_home = None
selected_marker = None
default_marker = FIXTURE_HOME / "Documents" / MARKER_NAME
report = {
    "bundle_id": BUNDLE_ID,
    "fixture_home": str(FIXTURE_HOME),
    "library_sha256": hashlib.sha256(LIBCRANE.read_bytes()).hexdigest(),
    "helper": "PASS",
    "supported_application": "PASS",
    "original_active_container": original,
    "stale_test_containers_removed": stale_containers_removed,
    "temporary_container_name": temporary_name,
    "rollback": "PENDING",
}
runtime_isolated = False
try:
    safe_mode_path = RUNTIME_STATE / "safe-mode-overrides.json"
    os.seteuid(0)
    os.setegid(0)
    try:
        safe_mode = json.loads(safe_mode_path.read_text()) if safe_mode_path.exists() else {}
    finally:
        os.setegid(501)
        os.seteuid(501)
    existing_override = (safe_mode.get("targets") or {}).get(BUNDLE_ID)
    if existing_override:
        prior_request = str(existing_override.get("request_id") or "")
        if prior_request.startswith("crane-uat-"):
            runtime_safe_mode("restartNormally")
            report["stale_uat_override_recovered"] = "PASS"
        else:
            raise RuntimeError("controlled fixture already has a runtime recovery override")
    registry_path = RUNTIME_STATE / "registry.json"
    os.seteuid(0)
    os.setegid(0)
    try:
        registry = json.loads(registry_path.read_text()) if registry_path.exists() else {}
    finally:
        os.setegid(501)
        os.seteuid(501)
    fixture_targets = [target for target in (registry.get("targets") or {}).values()
                       if isinstance(target, dict) and target.get("name") == BUNDLE_ID]
    if len(fixture_targets) > 1:
        raise RuntimeError("controlled fixture has ambiguous runtime targets")
    if fixture_targets:
        runtime_safe_mode("startWithoutTweaks")
        runtime_isolated = True
        report["unrelated_tweak_isolation"] = "PASS"
    else:
        report["unrelated_tweak_isolation"] = "SKIP_NO_REGISTERED_TWEAK_TARGET"

    temporary_object = send(ctypes.c_void_p, manager,
        "createNewContainerWithName:forApplicationWithIdentifier:",
        ns(temporary_name), application,
        argument_types=(ctypes.c_void_p, ctypes.c_void_p))
    stage("CREATE_CONTAINER_RETURNED")
    temporary = string(temporary_object)
    if not temporary or temporary == original:
        raise RuntimeError("Crane did not create a distinct temporary container")
    report["temporary_container"] = temporary
    identifiers = send(ctypes.c_void_p, manager,
        "containerIdentifiersOfApplicationWithIdentifier:", application,
        argument_types=(ctypes.c_void_p,))
    if not contains(identifiers, temporary_object):
        raise RuntimeError("temporary container is absent from Crane inventory")
    selected_home = container_home(manager, application, temporary)
    expected_prefix = str(FIXTURE_HOME / "Library/___Crane_Containers") + "/"
    if not selected_home or not selected_home.startswith(expected_prefix):
        raise RuntimeError("Crane returned an unsafe selected-container path: " + repr(selected_home))
    if pathlib.Path(selected_home).name != temporary:
        raise RuntimeError("Crane path does not end in the selected UUID")
    report["selected_home"] = selected_home

    send(None, manager,
        "setActiveContainerIdentifier:forApplicationWithIdentifier:reloadApplication:",
        temporary_object, application, False,
        argument_types=(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool))
    send(None, manager, "flushCFPrefsdCacheForApplicationWithIdentifier:",
         application, argument_types=(ctypes.c_void_p,))
    active = string(send(ctypes.c_void_p, manager,
        "activeContainerIdentifierForApplicationWithIdentifier:", application,
        argument_types=(ctypes.c_void_p,)))
    if active != temporary:
        raise RuntimeError("Crane did not activate the temporary container")
    report["container_activation"] = "PASS"

    write_handoff(temporary)
    selected_marker = pathlib.Path(selected_home) / "Documents" / MARKER_NAME
    launch = launch_url("__UAT_TOKEN__", selected_marker)
    stage("SELECTED_CONTAINER_LAUNCHED")
    if launch["marker"]["hooks"] < 1:
        raise RuntimeError("Crane loaded without installing its filesystem hook")
    if default_marker.is_file():
        raise RuntimeError("fixture marker was also written to the default container")
    report["fixture_pid"] = launch["pid"]
    report["hook_activation"] = "PASS"
    report["hook_count"] = launch["marker"]["hooks"]
    report["filesystem_redirection"] = "PASS"
    report["marker_path"] = launch["marker"]["path"]
    report["result"] = "PASS"
    stage("FUNCTIONAL_PASS")
except Exception as error:
    report["result"] = "FAIL"
    report["error"] = str(error)
finally:
    stop_fixture()
    rollback_errors = []
    try:
        if original_settings:
            send(None, manager, "setApplicationSettings:forApplicationWithIdentifier:",
                 original_settings, application,
                 argument_types=(ctypes.c_void_p, ctypes.c_void_p))
            send(None, manager, "_reloadPreferences")
        else:
            original_value = ns(original)
            send(None, manager,
                "setActiveContainerIdentifier:forApplicationWithIdentifier:reloadApplication:",
                original_value, application, False,
                argument_types=(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool))
        send(None, manager, "flushCFPrefsdCacheForApplicationWithIdentifier:",
             application, argument_types=(ctypes.c_void_p,))
        restored = string(send(ctypes.c_void_p, manager,
            "activeContainerIdentifierForApplicationWithIdentifier:", application,
            argument_types=(ctypes.c_void_p,))) or "DEFAULT"
        report["restored_active_container"] = restored
        if restored != original:
            rollback_errors.append("active container restored as " + restored)

        write_handoff(original)
        if temporary:
            send(None, manager,
                "deleteContainerWithIdentifier:forApplicationWithIdentifier:",
                ns(temporary), application,
                argument_types=(ctypes.c_void_p, ctypes.c_void_p))

        identifiers = send(ctypes.c_void_p, manager,
            "containerIdentifiersOfApplicationWithIdentifier:", application,
            argument_types=(ctypes.c_void_p,))
        if temporary and contains(identifiers, ns(temporary)):
            rollback_errors.append("temporary container remains in Crane inventory")

        rollback_marker = pathlib.Path(original_home) / "Documents" / MARKER_NAME
        rollback_launch = launch_url("__ROLLBACK_TOKEN__", rollback_marker)
        stage("ROLLBACK_CONTAINER_LAUNCHED")
        expected_hooks = 0 if original == "DEFAULT" else 1
        if ((rollback_launch["marker"]["hooks"] == 0) != (expected_hooks == 0)):
            rollback_errors.append("rollback hook state does not match original container")
        report["rollback_marker_path"] = rollback_launch["marker"]["path"]
        report["rollback_hook_count"] = rollback_launch["marker"]["hooks"]
    except Exception as rollback_error:
        rollback_errors.append(str(rollback_error))
    finally:
        stop_fixture()
        for candidate in (selected_marker, default_marker,
                          pathlib.Path(original_home) / "Documents" / MARKER_NAME):
            if candidate:
                defer_marker_cleanup(candidate)

        if runtime_isolated:
            try:
                runtime_safe_mode("restartNormally")
                report["runtime_override_restored"] = "PASS"
            except Exception as safe_mode_error:
                rollback_errors.append("runtime override restore failed: " + str(safe_mode_error))

    report["rollback_errors"] = rollback_errors
    report["rollback"] = "PASS" if not rollback_errors else "FAILED"
    if report["rollback"] != "PASS":
        report["result"] = "FAIL"

report["deferred_marker_cleanup"] = sorted(set(DEFERRED_MARKER_CLEANUP))

print(json.dumps(report, sort_keys=True))
stage("DONE")
'''


def fixture_metadata(udid: str) -> tuple[str, str]:
    completed = subprocess.run([
        os.environ.get("ZERO_SKY_PYTHON", sys.executable), "-m", "pymobiledevice3",
        "apps", "query", "com.liquidsky.SecurityTest", "--native", "--udid", udid,
    ], capture_output=True, text=True, timeout=30, check=True)
    record = json.loads(completed.stdout)["com.liquidsky.SecurityTest"]
    return str(record["Container"]), str(record.get("CFBundleShortVersionString") or "")


def mobile_bootstrap_context(worker: dict) -> str:
    """Resolve the exact trusted launcher for a mobile-domain test job.

    Crane's XPC service is published in iOS's foreground user bootstrap
    domain.  An SSH process remains in the recovery/root bootstrap domain even
    after setuid(501), so a direct SSH probe produces a false helper failure.
    The caller uses this launcher to create a bounded, one-shot test job in
    the same user domain as Control and the converted test application.
    """
    probe = r'''
import glob,hashlib,json,subprocess
expected="__LAUNCHCTL_SHA256__"
def sha(path):
 h=hashlib.sha256()
 with open(path,"rb") as stream:
  for block in iter(lambda:stream.read(1024*1024),b""):h.update(block)
 return h.hexdigest()
helpers=[]
for path in glob.glob("/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd"):
 try:
  if sha(path)==expected:helpers.append(path)
 except OSError:pass
if len(helpers)!=1:raise SystemExit("expected one trusted launchctl-srd")
print(json.dumps({"launchctl":helpers[0]}))
'''.replace("__LAUNCHCTL_SHA256__", TRUSTED_LAUNCHCTL_SHA256)
    completed = worker["ssh"](
        "/var/jb/usr/bin/python3 -", input_data=probe.encode(),
        timeout=20, check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            "unable to resolve Crane's mobile bootstrap context: " +
            completed.stderr.decode("utf-8", "replace")[-500:]
        )
    try:
        value = json.loads(completed.stdout.decode("utf-8", "replace"))
        launchctl = value["launchctl"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid mobile bootstrap context response") from error
    if not isinstance(launchctl, str) or not LAUNCHCTL_PATH.fullmatch(launchctl):
        raise RuntimeError("mobile bootstrap helper path is outside the reviewed Cryptex")
    return launchctl


def run_mobile_bootstrap_test(worker: dict, launchctl: str,
                              payload: str) -> subprocess.CompletedProcess:
    """Run one Crane UAT job in user/501 and return its captured output."""
    label = "com.liquidsky.crane.uat." + uuid.uuid4().hex
    encoded = base64.b64encode(payload.encode()).decode()
    launcher = r'''
import base64,json,os,pathlib,plistlib,subprocess,sys,time
ctl=__CTL__
label=__LABEL__
payload=base64.b64decode(__PAYLOAD__)
root=pathlib.Path("/var/jb/var/tmp")
script=root/(label+".py")
plist=root/(label+".plist")
stdout=root/(label+".stdout")
stderr=root/(label+".stderr")
for path in (script,plist,stdout,stderr):path.unlink(missing_ok=True)
script.write_bytes(payload);os.chown(script,0,0);os.chmod(script,0o600)
definition={
 "Label":label,
 "ProgramArguments":["/var/jb/usr/bin/python3",str(script)],
 "RunAtLoad":True,
 "KeepAlive":False,
 "ProcessType":"Interactive",
 "UserName":"root",
 "StandardOutPath":str(stdout),
 "StandardErrorPath":str(stderr),
}
plist.write_bytes(plistlib.dumps(definition,fmt=plistlib.FMT_BINARY,sort_keys=True))
os.chown(plist,0,0);os.chmod(plist,0o600)
boot=subprocess.run([ctl,"bootstrap","user/501",str(plist)],capture_output=True,text=True,timeout=15)
if boot.returncode:
 print(json.dumps({"bootstrap_returncode":boot.returncode,"stdout":"","stderr":boot.stderr[-2000:]}))
 raise SystemExit(0)
deadline=time.monotonic()+100
while time.monotonic()<deadline:
 if stdout.exists() and stdout.stat().st_size:
  time.sleep(.5)
  break
 time.sleep(.2)
out=stdout.read_text(errors="replace") if stdout.exists() else ""
err=stderr.read_text(errors="replace") if stderr.exists() else ""
state=subprocess.run([ctl,"print","user/501/"+label],capture_output=True,text=True,timeout=10)
subprocess.run([ctl,"bootout","user/501/"+label],capture_output=True,timeout=15)
for path in (script,plist,stdout,stderr):path.unlink(missing_ok=True)
print(json.dumps({"bootstrap_returncode":0,"stdout":out,"stderr":err,
                  "job_state":state.stdout[-2000:]}))
'''.replace("__CTL__", repr(launchctl)).replace(
        "__LABEL__", repr(label)).replace("__PAYLOAD__", repr(encoded))
    completed = worker["ssh"](
        "/var/jb/usr/bin/python3 -", input_data=launcher.encode(),
        timeout=120, check=False,
    )
    if completed.returncode:
        return completed
    try:
        envelope = json.loads(completed.stdout.decode("utf-8", "replace"))
        status = int(envelope.get("bootstrap_returncode", 1))
        stdout = str(envelope.get("stdout", "")).encode()
        stderr = str(envelope.get("stderr", "")).encode()
        if status == 0 and not stdout:
            status = 1
            stderr = (("Crane mobile-domain UAT produced no report; job state:\n" +
                       str(envelope.get("job_state", ""))[-1000:] + "\nstages:\n").encode()
                      + stderr)
        return subprocess.CompletedProcess([], status, stdout, stderr)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        return subprocess.CompletedProcess(
            [], 1, completed.stdout,
            completed.stderr + ("invalid mobile-domain UAT envelope: " +
                                str(error)).encode(),
        )


def cleanup_remote_markers(worker: dict, fixture_home: str,
                           candidates: list[str]) -> dict:
    """Remove only this UAT's fixed marker beneath the controlled fixture."""
    root = pathlib.PurePosixPath(fixture_home)
    approved: list[str] = []
    for value in candidates:
        path = pathlib.PurePosixPath(value)
        if not path.is_absolute() or path.name != "0sky-crane-uat.txt":
            raise RuntimeError("refused an unexpected Crane UAT cleanup path")
        try:
            path.relative_to(root)
        except ValueError as error:
            raise RuntimeError("refused Crane UAT cleanup outside the fixture") from error
        approved.append(str(path))
    cleanup = r'''
import json,os
paths=json.loads(__PATHS__)
results={}
for path in paths:
 try:
  os.unlink(path)
  results[path]="REMOVED"
 except FileNotFoundError:
  results[path]="ABSENT"
 except OSError as error:
  results[path]="ERROR:"+repr(error)
print(json.dumps(results,sort_keys=True))
'''.replace("__PATHS__", repr(json.dumps(sorted(set(approved)))))
    completed = worker["ssh"](
        "/var/jb/usr/bin/python3 -", input_data=cleanup.encode(),
        timeout=20, check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            "paired worker could not clean Crane UAT markers: " +
            completed.stderr.decode("utf-8", "replace")[-500:]
        )
    result = json.loads(completed.stdout.decode("utf-8", "replace"))
    failures = {path: state for path, state in result.items()
                if not str(state).startswith(("REMOVED", "ABSENT"))}
    if failures:
        raise RuntimeError("Crane UAT marker cleanup failed: " + repr(failures))
    return result


REMOTE_CRANE_CONTROL = r'''
import base64,ctypes,hashlib,json,os,re,signal,time
command=json.loads(base64.b64decode("__COMMAND__"))
bundle="com.liquidsky.SecurityTest"
lib="/var/jb/usr/lib/libcrane.dylib"
os.setegid(501);os.seteuid(501)
ctypes.CDLL("/System/Library/Frameworks/Foundation.framework/Foundation",mode=8)
ctypes.CDLL(lib,mode=8)
objc=ctypes.CDLL("/usr/lib/libobjc.A.dylib")
objc.objc_getClass.argtypes=[ctypes.c_char_p];objc.objc_getClass.restype=ctypes.c_void_p
objc.sel_registerName.argtypes=[ctypes.c_char_p];objc.sel_registerName.restype=ctypes.c_void_p
message=objc.objc_msgSend
def cls(name):return objc.objc_getClass(name.encode())
def sel(name):return objc.sel_registerName(name.encode())
def send(restype,receiver,name,*args,argtypes=()):
 message.restype=restype;message.argtypes=[ctypes.c_void_p,ctypes.c_void_p,*argtypes]
 return message(receiver,sel(name),*args)
def ns(value):return send(ctypes.c_void_p,cls("NSString"),"stringWithUTF8String:",value.encode(),argtypes=(ctypes.c_char_p,))
def text(value):
 if not value:return None
 raw=send(ctypes.c_char_p,value,"UTF8String")
 return raw.decode("utf-8","replace") if raw else None
def values(array):
 count=send(ctypes.c_ulong,array,"count") if array else 0
 return [send(ctypes.c_void_p,array,"objectAtIndex:",i,argtypes=(ctypes.c_ulong,)) for i in range(count)]
manager=send(ctypes.c_void_p,cls("CraneManager"),"sharedManager")
if not manager:raise RuntimeError("CraneManager unavailable")
def timeout(_sig,_frame):raise TimeoutError("Crane helper probe timed out")
signal.signal(signal.SIGALRM,timeout);signal.alarm(15)
try:helper=bool(send(ctypes.c_bool,manager,"cranehelperdConnectionWorks"))
finally:signal.alarm(0)
if not helper:raise RuntimeError("Crane helper connection unavailable")
app=ns(bundle)
if not send(ctypes.c_bool,manager,"isApplicationSupportedByCrane:",app,argtypes=(ctypes.c_void_p,)):
 raise RuntimeError("controlled fixture unsupported")
def identifiers():
 return send(ctypes.c_void_p,manager,"containerIdentifiersOfApplicationWithIdentifier:",app,argtypes=(ctypes.c_void_p,))
def identifier_texts():return [text(value) for value in values(identifiers())]
def container_home(identifier):
 paths=send(ctypes.c_void_p,manager,"pathsAssociatedToContainerWithIdentifier:ofApplicationWithIdentifier:",ns(identifier),app,argtypes=(ctypes.c_void_p,ctypes.c_void_p))
 home=send(ctypes.c_void_p,paths,"objectForKey:",app,argtypes=(ctypes.c_void_p,)) if paths else None
 return text(home)
def remove_metadata(removals):
 settings=send(ctypes.c_void_p,manager,"applicationSettingsForApplicationWithIdentifier:",app,argtypes=(ctypes.c_void_p,))
 mutable=send(ctypes.c_void_p,settings,"mutableCopy") if settings else None
 if not mutable:return []
 key=ns("Containers")
 containers=send(ctypes.c_void_p,mutable,"objectForKey:",key,argtypes=(ctypes.c_void_p,))
 mutable_containers=send(ctypes.c_void_p,containers,"mutableCopy") if containers else None
 if not mutable_containers:return []
 removed=[]
 entries=values(mutable_containers)
 for index in range(len(entries)-1,-1,-1):
  identifier=text(send(ctypes.c_void_p,entries[index],"objectForKey:",ns("identifier"),argtypes=(ctypes.c_void_p,)))
  if identifier in removals:
   send(None,mutable_containers,"removeObjectAtIndex:",index,argtypes=(ctypes.c_ulong,));removed.append(identifier)
 send(None,mutable,"setObject:forKey:",mutable_containers,key,argtypes=(ctypes.c_void_p,ctypes.c_void_p))
 send(None,manager,"setApplicationSettings:forApplicationWithIdentifier:",mutable,app,argtypes=(ctypes.c_void_p,ctypes.c_void_p))
 send(None,manager,"_reloadPreferences")
 return sorted(set(removed))
operation=command.get("operation")
if operation=="prepare":
 original=text(send(ctypes.c_void_p,manager,"activeContainerIdentifierForApplicationWithIdentifier:",app,argtypes=(ctypes.c_void_p,))) or "DEFAULT"
 removed=[]
 for value in values(identifiers()):
  identifier=text(value)
  if not identifier or identifier==original:continue
  name=text(send(ctypes.c_void_p,manager,"displayNameForContainerWithIdentifier:ofApplicationWithIdentifier:shouldUseShortVersion:",value,app,False,argtypes=(ctypes.c_void_p,ctypes.c_void_p,ctypes.c_bool))) or ""
  if name.startswith("0-Sky UAT "):
   send(None,manager,"deleteContainerWithIdentifier:forApplicationWithIdentifier:",value,app,argtypes=(ctypes.c_void_p,ctypes.c_void_p));removed.append(identifier)
 name="0-Sky UAT "+command["suffix"]
 created=send(ctypes.c_void_p,manager,"createNewContainerWithName:forApplicationWithIdentifier:",ns(name),app,argtypes=(ctypes.c_void_p,ctypes.c_void_p))
 temporary=text(created)
 if not temporary or temporary==original:raise RuntimeError("Crane did not create a distinct container")
 home=container_home(temporary)
 if not home:raise RuntimeError("Crane did not provide a temporary container path")
 send(None,manager,"setActiveContainerIdentifier:forApplicationWithIdentifier:reloadApplication:",created,app,False,argtypes=(ctypes.c_void_p,ctypes.c_void_p,ctypes.c_bool))
 send(None,manager,"flushCFPrefsdCacheForApplicationWithIdentifier:",app,argtypes=(ctypes.c_void_p,))
 active=text(send(ctypes.c_void_p,manager,"activeContainerIdentifierForApplicationWithIdentifier:",app,argtypes=(ctypes.c_void_p,))) or "DEFAULT"
 if active!=temporary:raise RuntimeError("Crane did not activate the temporary container")
 print(json.dumps({"operation":"prepare","helper":"PASS","supported":"PASS","original":original,"original_home":container_home(original),"temporary":temporary,"selected_home":home,"stale_removed":removed,"library_sha256":hashlib.sha256(open(lib,"rb").read()).hexdigest()},sort_keys=True))
elif operation=="restore":
 original=str(command["original"]);temporary=str(command["temporary"])
 uuid_pattern=r"^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$"
 if original!="DEFAULT" and not re.fullmatch(uuid_pattern,original):raise RuntimeError("invalid original container identifier")
 if not re.fullmatch(uuid_pattern,temporary):raise RuntimeError("invalid temporary container identifier")
 send(None,manager,"setActiveContainerIdentifier:forApplicationWithIdentifier:reloadApplication:",ns(original),app,False,argtypes=(ctypes.c_void_p,ctypes.c_void_p,ctypes.c_bool))
 send(None,manager,"flushCFPrefsdCacheForApplicationWithIdentifier:",app,argtypes=(ctypes.c_void_p,))
 send(None,manager,"deleteContainerWithIdentifier:forApplicationWithIdentifier:",ns(temporary),app,argtypes=(ctypes.c_void_p,ctypes.c_void_p))
 deadline=time.monotonic()+10
 while temporary in identifier_texts() and time.monotonic()<deadline:time.sleep(.2)
 active=text(send(ctypes.c_void_p,manager,"activeContainerIdentifierForApplicationWithIdentifier:",app,argtypes=(ctypes.c_void_p,))) or "DEFAULT"
 if active!=original:raise RuntimeError("Crane active container rollback failed")
 present=temporary in identifier_texts()
 print(json.dumps({"operation":"restore","active":active,"temporary_removed":not present,"bridge_cleanup_required":present},sort_keys=True))
elif operation=="remove_metadata":
 removals=[]
 for identifier in command.get("identifiers") or []:
  if not re.fullmatch(r"^[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}$",str(identifier)):raise RuntimeError("invalid metadata cleanup identifier")
  removals.append(str(identifier))
 removed=remove_metadata(set(removals))
 remaining=[identifier for identifier in removals if identifier in identifier_texts()]
 if remaining:raise RuntimeError("Crane metadata cleanup failed: "+repr(remaining))
 print(json.dumps({"operation":"remove_metadata","removed":removed,"remaining":remaining},sort_keys=True))
elif operation=="verify_restore":
 original=str(command["original"]);temporary=str(command["temporary"])
 active=text(send(ctypes.c_void_p,manager,"activeContainerIdentifierForApplicationWithIdentifier:",app,argtypes=(ctypes.c_void_p,))) or "DEFAULT"
 present=temporary in identifier_texts()
 if active!=original:raise RuntimeError("Crane active container verification failed")
 if present:raise RuntimeError("Crane temporary container remains after paired cleanup")
 print(json.dumps({"operation":"verify_restore","active":active,"temporary_absent":True},sort_keys=True))
else:raise RuntimeError("unsupported Crane control operation")
'''


def run_crane_control(worker: dict, launchctl: str, command: dict) -> dict:
    encoded = base64.b64encode(json.dumps(command, sort_keys=True).encode()).decode()
    payload = REMOTE_CRANE_CONTROL.replace("__COMMAND__", encoded)
    completed = run_mobile_bootstrap_test(worker, launchctl, payload)
    if completed.returncode:
        raise RuntimeError(
            "Crane user-domain control failed: " +
            completed.stderr.decode("utf-8", "replace")[-1500:]
        )
    lines = completed.stdout.decode("utf-8", "replace").strip().splitlines()
    if not lines:
        raise RuntimeError("Crane user-domain control returned no result")
    return json.loads(lines[-1])


def run_fixture_probe(worker: dict, fixture_home: str, selected_home: str,
                      container: str, token: str) -> dict:
    root = pathlib.PurePosixPath(fixture_home)
    selected = pathlib.PurePosixPath(selected_home)
    if selected != root:
        expected_parent = root / "Library/___Crane_Containers"
        if selected.parent != expected_parent:
            raise RuntimeError("refused a Crane container path outside the fixture")
    marker = selected / "Documents/0sky-crane-uat.txt"
    default_marker = root / "Documents/0sky-crane-uat.txt"
    config = {
        "fixture_home": str(root), "selected_home": str(selected),
        "container": container, "token": token,
        "marker": str(marker), "default_marker": str(default_marker),
    }
    script = r'''
import json,os,pathlib,signal,subprocess,time
c=json.loads(__CONFIG__)
root=pathlib.Path(c["fixture_home"]);selected=pathlib.Path(c["selected_home"])
marker=pathlib.Path(c["marker"]);default_marker=pathlib.Path(c["default_marker"])
handoff=root/"Library/0Sky/Crane/active-container"
def pid():
 out=subprocess.run(["ps","-axo","pid=,command="],capture_output=True,text=True,timeout=10,check=True).stdout
 for line in out.splitlines():
  if "/ZeroSkySecurityTest.app/ZeroSkySecurityTest" in line:
   head=line.strip().split(None,1)[0]
   if head.isdigit():return int(head)
def stop():
 value=pid()
 if value:
  try:os.kill(value,signal.SIGTERM)
  except ProcessLookupError:pass
  for _ in range(40):
   if pid()!=value:break
   time.sleep(.1)
 return value
stop()
for path in {marker,default_marker}:
 try:path.unlink()
 except FileNotFoundError:pass
handoff.parent.mkdir(parents=True,exist_ok=True)
if c["container"]=="DEFAULT":
 try:handoff.unlink()
 except FileNotFoundError:pass
else:
 handoff.write_text(c["container"]+"\n");os.chown(handoff,501,501);handoff.chmod(0o600)
opened=subprocess.run(["/var/jb/usr/bin/uiopen","--url","zeroskytest://write/"+c["token"]],capture_output=True,text=True,timeout=20)
if opened.returncode:raise RuntimeError("fixture launch failed: "+opened.stderr[-300:])
deadline=time.monotonic()+20;result=None
while time.monotonic()<deadline:
 value=pid()
 if value and marker.is_file():
  content=marker.read_text(errors="replace")
  prefix=c["token"]+"|hooks="
  if content.startswith(prefix):
   hooks=int(content[len(prefix):]);time.sleep(.5)
   if pid()==value:result={"pid":value,"hooks":hooks,"marker":str(marker)};break
 time.sleep(.2)
if not result:raise RuntimeError("fixture did not remain alive and write the expected marker")
if selected!=root and default_marker.exists():raise RuntimeError("Crane also wrote into the default container")
stop();print(json.dumps(result,sort_keys=True))
'''.replace("__CONFIG__", repr(json.dumps(config, sort_keys=True)))
    completed = worker["ssh"](
        "/var/jb/usr/bin/python3 -", input_data=script.encode(),
        timeout=40, check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            "controlled fixture probe failed: " +
            completed.stderr.decode("utf-8", "replace")[-1500:]
        )
    return json.loads(completed.stdout.decode("utf-8", "replace").strip().splitlines()[-1])


def cleanup_remote_container(worker: dict, fixture_home: str,
                             selected_home: str, identifier: str) -> dict:
    root = pathlib.PurePosixPath(fixture_home)
    selected = pathlib.PurePosixPath(selected_home)
    if (selected.parent != root / "Library/___Crane_Containers" or
            selected.name != identifier or
            not re.fullmatch(r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}",
                             identifier)):
        raise RuntimeError("refused an unsafe Crane container cleanup path")
    config = {"root": str(root), "selected": str(selected)}
    script = r'''
import json,pathlib,shutil
c=json.loads(__CONFIG__);root=pathlib.Path(c["root"]);selected=pathlib.Path(c["selected"])
if selected.parent!=root/"Library/___Crane_Containers":raise SystemExit("unsafe cleanup path")
if selected.exists():shutil.rmtree(selected)
if selected.exists():raise SystemExit("container directory remains")
print(json.dumps({"path":str(selected),"removed":True},sort_keys=True))
'''.replace("__CONFIG__", repr(json.dumps(config, sort_keys=True)))
    completed = worker["ssh"](
        "/var/jb/usr/bin/python3 -", input_data=script.encode(),
        timeout=20, check=False,
    )
    if completed.returncode:
        raise RuntimeError(
            "paired Crane container cleanup failed: " +
            completed.stderr.decode("utf-8", "replace")[-1000:]
        )
    return json.loads(completed.stdout.decode("utf-8", "replace").strip())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--instance-name", required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    identity = asyncio.run(usb_identity(args.udid))
    if identity.get("udid") != args.udid:
        parser.error("exact USB device identity does not match")
    configured = profiles(instance_name=args.instance_name)
    if args.udid not in configured:
        parser.error("paired profile does not match the selected device")
    fixture_home, fixture_version = fixture_metadata(args.udid)
    if not pathlib.PurePosixPath(fixture_home).is_absolute():
        parser.error("fixture data container is not absolute")
    worker = worker_namespace(configured[args.udid][1])
    default_marker = str(pathlib.PurePosixPath(fixture_home) /
                         "Documents/0sky-crane-uat.txt")
    cleanup_remote_markers(worker, fixture_home, [default_marker])
    launchctl = mobile_bootstrap_context(worker)
    report = {
        "udid": args.udid,
        "fixture_version": fixture_version,
        "checked_at": int(time.time()),
        "bundle_id": "com.liquidsky.SecurityTest",
        "fixture_home": fixture_home,
        "result": "FAIL",
        "rollback": "PENDING",
    }
    prepare = None
    cleanup_candidates = [default_marker]
    rollback_errors: list[str] = []
    try:
        prepare = run_crane_control(worker, launchctl, {
            "operation": "prepare", "suffix": uuid.uuid4().hex[:8],
        })
        report["prepare"] = prepare
        report["helper"] = prepare.get("helper")
        report["supported_application"] = prepare.get("supported")
        report["original_active_container"] = prepare["original"]
        report["temporary_container"] = prepare["temporary"]
        report["selected_home"] = prepare["selected_home"]
        report["library_sha256"] = prepare["library_sha256"]
        stale_ids = list(prepare.get("stale_removed") or [])
        if stale_ids:
            stale_cleanup = []
            for stale_id in stale_ids:
                stale_home = str(pathlib.PurePosixPath(fixture_home) /
                                 "Library/___Crane_Containers" / stale_id)
                stale_cleanup.append(cleanup_remote_container(
                    worker, fixture_home, stale_home, stale_id))
            report["stale_container_cleanup"] = stale_cleanup
            report["stale_metadata_cleanup"] = run_crane_control(
                worker, launchctl, {
                    "operation": "remove_metadata", "identifiers": stale_ids,
                })
        cleanup_candidates.append(str(pathlib.PurePosixPath(
            prepare["selected_home"]) / "Documents/0sky-crane-uat.txt"))
        selected = run_fixture_probe(
            worker, fixture_home, prepare["selected_home"], prepare["temporary"],
            "osky-" + uuid.uuid4().hex,
        )
        report["selected_container_probe"] = selected
        if int(selected.get("hooks", 0)) < 1:
            raise RuntimeError("Crane loaded without installing its filesystem hook")
        report["container_activation"] = "PASS"
        report["hook_activation"] = "PASS"
        report["filesystem_redirection"] = "PASS"
        report["result"] = "PASS"
    except Exception as error:
        report["error"] = str(error)
    finally:
        if prepare:
            try:
                restored = run_crane_control(worker, launchctl, {
                    "operation": "restore",
                    "original": prepare["original"],
                    "temporary": prepare["temporary"],
                })
                report["restore"] = restored
                if restored.get("bridge_cleanup_required"):
                    report["paired_container_cleanup"] = cleanup_remote_container(
                        worker, fixture_home, prepare["selected_home"],
                        prepare["temporary"])
                    report["paired_metadata_cleanup"] = run_crane_control(
                        worker, launchctl, {
                            "operation": "remove_metadata",
                            "identifiers": [prepare["temporary"]],
                        })
                report["restore_verification"] = run_crane_control(
                    worker, launchctl, {
                        "operation": "verify_restore",
                        "original": prepare["original"],
                        "temporary": prepare["temporary"],
                    })
                original_home = prepare.get("original_home") or fixture_home
                cleanup_candidates.append(str(pathlib.PurePosixPath(
                    original_home) / "Documents/0sky-crane-uat.txt"))
                rollback_probe = run_fixture_probe(
                    worker, fixture_home, original_home, prepare["original"],
                    "osky-rollback-" + uuid.uuid4().hex,
                )
                report["rollback_probe"] = rollback_probe
                expected_hooks = 0 if prepare["original"] == "DEFAULT" else 1
                if ((int(rollback_probe.get("hooks", 0)) == 0) !=
                        (expected_hooks == 0)):
                    raise RuntimeError("rollback hook state does not match the original container")
            except Exception as rollback_error:
                rollback_errors.append(str(rollback_error))
        else:
            rollback_errors.append("prepare did not create a temporary container")
        try:
            report["host_marker_cleanup"] = cleanup_remote_markers(
                worker, fixture_home, cleanup_candidates)
        except Exception as cleanup_error:
            rollback_errors.append(str(cleanup_error))
    report["rollback_errors"] = rollback_errors
    report["rollback"] = "PASS" if not rollback_errors else "FAILED"
    if rollback_errors:
        report["result"] = "FAIL"
    atomic_write(args.output.resolve(),
                 (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps(report, indent=2, sort_keys=True))
    if report.get("result") != "PASS" or report.get("rollback") != "PASS":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
