#!/usr/bin/env python3
"""Diagnose or repair each configured 0-Sky connection using exact USB identity."""
import argparse
import asyncio
from collections import Counter
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import runpy
import shutil
import shlex
import subprocess
import sys
import time
import uuid

from device_python import ensure_device_python, select_device_python

HERE = Path(__file__).resolve().parent
HOST_TOOLS = HERE.parents[1] / "bridge/HostTools"
SUPPORT = Path.home() / "Library/Application Support/0-Sky"

def profiles(agents=None, instance_name=None):
    agents = agents or Path.home()/"Library/LaunchAgents"
    found = {}
    for path in sorted(agents.glob("com.liquidskysecurity.crypstore-worker.*.plist")):
        if instance_name and path.name != f"com.liquidskysecurity.crypstore-worker.{instance_name}.plist":
            continue
        value = plistlib.loads(path.read_bytes())
        udid = value.get("EnvironmentVariables",{}).get("CRYPSTORE_DEVICE_UDID")
        if not udid:
            continue
        workers = [Path(arg) for arg in value.get("ProgramArguments",[])
                   if arg.endswith("/crypstore_worker.py")]
        if len(workers) != 1 or not workers[0].is_file():
            continue
        if udid in found:
            raise ValueError("Multiple active worker definitions for "+udid)
        found[udid] = (path,value)
    return found


def configured_instances(agents=None):
    """Enumerate exact worker identities without hiding duplicate UDID profiles."""
    agents = agents or Path.home()/"Library/LaunchAgents"
    prefix = "com.liquidskysecurity.crypstore-worker."
    result = []
    for path in sorted(agents.glob(prefix + "*.plist")):
        instance_name = path.name[len(prefix):-len(".plist")]
        for udid in profiles(agents, instance_name):
            result.append((udid, instance_name))
    return result

async def usb_identity(udid):
    from pymobiledevice3.usbmux import list_devices
    from pymobiledevice3.lockdown import create_using_usbmux
    devices = await asyncio.wait_for(list_devices(),timeout=10)
    if not any(d.serial == udid and str(d.connection_type).upper() == "USB" for d in devices):
        raise RuntimeError("USB_NOT_CONNECTED: connect the selected device by USB")
    async with await asyncio.wait_for(create_using_usbmux(serial=udid,
            connection_type="USB",autopair=False),timeout=15) as device:
        if device.udid != udid or not device.paired:
            raise RuntimeError("USB_IDENTITY_OR_PAIRING_INVALID")
        values = await device.get_value()
        return {"udid":device.udid,"product":values.get("ProductType"),
                "version":values.get("ProductVersion"),"build":values.get("BuildVersion")}

def interpreter_status(python):
    probe = "import sys,importlib.metadata,cryptography,pymobiledevice3; print(sys.version.split()[0]); print(importlib.metadata.version('pymobiledevice3'))"
    try:
        p = subprocess.run([python,"-c",probe],capture_output=True,text=True,timeout=15)
        return {"ready":p.returncode == 0,"version":p.stdout.strip().splitlines(),
                "error":p.stderr.strip().splitlines()[-1] if p.stderr.strip() else None}
    except (OSError,subprocess.TimeoutExpired) as error:
        return {"ready":False,"error":type(error).__name__}

def worker_namespace(value):
    env = value["EnvironmentVariables"]
    # Each device runs in a separate process so environment/module state cannot
    # accidentally retain another device's host, port, identity or private key.
    for name in list(os.environ):
        if name.startswith("CRYPSTORE_"):
            del os.environ[name]
    os.environ.update(env)
    worker = next(Path(arg) for arg in value["ProgramArguments"] if arg.endswith("/crypstore_worker.py"))
    return runpy.run_path(str(worker),run_name="connection_repair_worker")

def ssh_probe(namespace):
    result = namespace["ssh"]("id -u; /var/jb/usr/bin/python3 --version",timeout=20,check=False)
    return {"connected":result.returncode == 0 and result.stdout.splitlines()[:1] == [b"0"],
            "exit":result.returncode,"stdout":result.stdout.decode(errors="replace")[:256],
            "error":result.stderr.decode(errors="replace")[:1500]}

def atomic_write(path,data,mode=0o600):
    if path.is_symlink():
        raise RuntimeError("Refusing to replace a symbolic-link configuration")
    temporary = path.with_name("."+path.name+".connection-repair-"+str(os.getpid()))
    fd = os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    with os.fdopen(fd,"wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary,path)

def repair_host_profile(path,config_path,env,alias,output,fingerprint=None):
    original_plist = path.read_bytes()
    original_config = config_path.read_bytes()
    config = json.loads(original_config)
    new_value = plistlib.loads(original_plist)
    existing = new_value["ProgramArguments"][0]
    status = interpreter_status(existing)
    versions = status.get("version",[])
    if status["ready"] and versions and tuple(map(int,versions[0].split(".")[:2])) >= (3,12):
        try:
            python = select_device_python(existing)
        except ValueError:
            python = select_device_python()
    else:
        python = select_device_python()
    new_value["ProgramArguments"][0] = python
    new_value["EnvironmentVariables"]["SRD_PYTHON"] = python
    new_value["EnvironmentVariables"]["CRYPSTORE_DEVICE_HOST_ALIAS"] = alias
    if fingerprint is not None:
        new_value["EnvironmentVariables"]["CRYPSTORE_HOST_KEY_FINGERPRINT"] = fingerprint
    config.update(ssh_host=env["CRYPSTORE_DEVICE_HOST"],ssh_port=str(env["CRYPSTORE_DEVICE_PORT"]),
                  ssh_remote_port=str(env.get("CRYPSTORE_DEVICE_REMOTE_PORT","22")),
                  ssh_key=env["CRYPSTORE_DEVICE_KEY"],ssh_known_hosts=env["CRYPSTORE_DEVICE_KNOWN_HOSTS"],
                  ssh_host_alias=alias)
    updated = plistlib.dumps(new_value,fmt=plistlib.FMT_XML)
    changed = updated != original_plist or json.loads(original_config) != config
    if not changed:
        return False,python
    backup = output/("before-"+uuid.uuid4().hex)
    backup.mkdir(mode=0o700)
    atomic_write(backup/path.name,original_plist)
    atomic_write(backup/"config.json",original_config)
    target = f"gui/{os.getuid()}/{new_value['Label']}"
    try:
        atomic_write(config_path,(json.dumps(config,indent=2,sort_keys=True)+"\n").encode())
        atomic_write(path,updated)
        subprocess.run(["/bin/launchctl","bootout",target],capture_output=True,timeout=15,check=False)
        deadline = time.monotonic()+15
        while subprocess.run(["/bin/launchctl","print",target],capture_output=True,timeout=5).returncode == 0:
            if time.monotonic() >= deadline:
                raise RuntimeError("Worker did not unload before restart")
            time.sleep(.25)
        started = subprocess.run(["/bin/launchctl","bootstrap",f"gui/{os.getuid()}",str(path)],capture_output=True,timeout=20)
        if started.returncode:
            raise RuntimeError("Worker restart failed: "+started.stderr.decode(errors="replace")[:512])
    except Exception:
        atomic_write(config_path,original_config)
        atomic_write(path,original_plist)
        subprocess.run(["/bin/launchctl","bootstrap",f"gui/{os.getuid()}",str(path)],capture_output=True,timeout=20,check=False)
        raise
    atomic_write(output/"host-repair.json",(json.dumps({"changed":True,"backup":str(backup),
        "port":str(env["CRYPSTORE_DEVICE_PORT"]),"interpreter":python},indent=2)+"\n").encode())
    return True,python

def ensure_persistent_tunnel(path,env):
    """Use a matching persistent USB job or create one; never borrow another UDID."""
    import pair
    udid = env["CRYPSTORE_DEVICE_UDID"]
    port = str(env["CRYPSTORE_DEVICE_PORT"])
    remote_port = str(env.get("CRYPSTORE_DEVICE_REMOTE_PORT","22"))
    if not remote_port.isdigit() or not 1 <= int(remote_port) <= 65535:
        raise RuntimeError("Invalid configured device SSH port")
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise RuntimeError("Invalid configured USB port")
    matching = []
    for candidate in path.parent.glob("com.liquidskysecurity.crypstore-usbmux.*.plist"):
        value = plistlib.loads(candidate.read_bytes())
        argv = value.get("ProgramArguments",[])
        expected = ["-s","127.0.0.1","-u",udid,port+":"+remote_port]
        if argv[1:] == expected and Path(argv[0]).name == "iproxy" and value.get("KeepAlive"):
            matching.append((candidate,value))
    if len(matching) > 1:
        raise RuntimeError("Multiple persistent USB jobs claim the same device and port")
    if pair.tcp_open("127.0.0.1",port) and not pair.exact_iproxy_present(udid,port,remote_port):
        raise RuntimeError("Configured USB port is occupied by an unrelated listener")
    created = False
    if matching:
        candidate,value = matching[0]
    else:
        # Do not kill a manually managed listener to replace it with launchd.
        if pair.tcp_open("127.0.0.1",port):
            raise RuntimeError("USB route is manual; stop its exact-device listener before provisioning the persistent job")
        executable = shutil.which("iproxy")
        if not executable: raise RuntimeError("iproxy is not installed")
        label = plistlib.loads(path.read_bytes())["Label"].replace(".crypstore-worker.",".crypstore-usbmux.")
        candidate = path.with_name(label+".plist")
        if candidate.exists(): raise RuntimeError("Persistent USB definition exists with conflicting identity or port")
        value = {"Label":label,"ProgramArguments":[executable,"-s","127.0.0.1","-u",udid,port+":"+remote_port],
                 "RunAtLoad":True,"KeepAlive":True,"ThrottleInterval":5}
        atomic_write(candidate,plistlib.dumps(value))
        created = True
    target = f"gui/{os.getuid()}/{value['Label']}"
    try:
        loaded = subprocess.run(["/bin/launchctl","print",target],capture_output=True,timeout=15)
        if loaded.returncode:
            started = subprocess.run(["/bin/launchctl","bootstrap",f"gui/{os.getuid()}",str(candidate)],capture_output=True,timeout=20)
            if started.returncode: raise RuntimeError("Persistent USB job could not be loaded")
        deadline = time.monotonic()+10
        while time.monotonic() < deadline:
            if pair.tcp_open("127.0.0.1",port) and pair.exact_iproxy_present(udid,port,remote_port):
                return {"launch_agent":str(candidate),"created":created,"port":port,"remote_port":remote_port}
            time.sleep(.25)
        raise RuntimeError("Persistent USB job did not bind the selected device")
    except Exception:
        if created:
            subprocess.run(["/bin/launchctl","bootout",target],capture_output=True,timeout=15,check=False)
            candidate.unlink()
        raise

def repair(udid,path,value,identity,output,recover_ssh=False,reboot_recovery=False,authorize_password=False):
    sys.path.insert(0,str(HOST_TOOLS))
    from apple_device_pairing import MacPairingCoordinator
    import pair
    env = value["EnvironmentVariables"]
    instance = Path(env["CRYPSTORE_INSTANCE_DIR"])
    config_path = instance/"config.json"
    config = json.loads(config_path.read_text())
    if config.get("udid") != udid or instance.is_symlink():
        raise RuntimeError("Instance identity does not match the selected device")
    host = env["CRYPSTORE_DEVICE_HOST"]
    port = env.get("CRYPSTORE_DEVICE_PORT","22")
    remote_port = env.get("CRYPSTORE_DEVICE_REMOTE_PORT","22")
    if host not in ("127.0.0.1","localhost"):
        raise RuntimeError("Repair requires a configured exact-device loopback USB route")
    key = Path(env["CRYPSTORE_DEVICE_KEY"])
    if not key.is_file() or key.stat().st_mode & 0o077:
        raise RuntimeError("Configured private-key file is unavailable or its mode is not 0600")
    pin = Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"])
    if pin != instance/"device-known-hosts":
        raise RuntimeError("Host-key pin belongs outside the selected instance")
    alias = pair.device_host_alias(udid)
    if env.get("CRYPSTORE_DEVICE_HOST_ALIAS",alias) != alias:
        raise RuntimeError("Configured host-key alias does not match the device")
    # Validate listener ownership before enrolling or modifying the profile.
    persistent_tunnel = ensure_persistent_tunnel(path,env)
    temporary_tunnel = pair.prepare_loopback_tunnel(host,str(port),udid,remote_port)
    try:
        pairing = asyncio.run(MacPairingCoordinator(SUPPORT,timeout=45).run(
            udid,allow_pair=False,allow_host_enrollment=True))
        if pairing.get("status") != "verified":
            raise RuntimeError(pairing.get("errorCode","PAIR_VERIFY_FAILED")+": "+pairing.get("userMessage",""))
        # USB was identity-verified above. Missing pins may be enrolled here;
        # existing pins are never silently rotated or relaxed.
        try:
            fingerprints = pair.ensure_device_host_key_pin(host=host,port=str(port),
                udid=udid,known_hosts=pin,allow_create=True,allow_replace=False)
        except RuntimeError as error:
            # A stopped SSH service cannot answer keyscan. The recovery
            # Cryptex uses the existing pin and proves root before changing
            # the persistent Mac route; never relax a mismatched host key.
            if not recover_ssh or str(error) != "device SSH service did not provide a usable host key":
                raise
            from stage_srdssh_recovery import recover
            recovery = recover(udid,key,output,instance.name)
            refreshed = plistlib.loads(path.read_bytes())
            result = repair(udid,path,refreshed,identity,output)
            result["key_enrollment"] = recovery
            return result
        changed,python = repair_host_profile(path,config_path,env,alias,output,pair.key_fingerprint(key))
        base = pair.ssh_base(host,str(port),key,known_hosts=pin,host_alias=alias)
        recovery = None
        try:
            p = pair.ssh(base,"id -u")
        except RuntimeError as error:
            # A service can publish its pinned host key and still stall before
            # the SSH banner (the iOS 27 failure seen after a userspace service
            # crash).  Explicit --recover-ssh authorization covers that state
            # as well as a missing key or rejected client key.  Retry exactly
            # once with recovery disabled so this cannot recurse indefinitely.
            if "Permission denied" not in str(error) and recover_ssh:
                from stage_srdssh_recovery import recover
                recovery = recover(udid,key,output,instance.name)
                refreshed=plistlib.loads(path.read_bytes())
                result=repair(udid,path,refreshed,identity,output,
                              recover_ssh=False)
                result["key_enrollment"]=recovery
                return result
            if "Permission denied" not in str(error):
                raise
            if authorize_password:
                from authorize_device_key import authorize
                recovery = authorize(udid,key,base,output)
            elif not recover_ssh:
                raise RuntimeError("SSH_CLIENT_KEY_NOT_AUTHORIZED: host configuration repaired; authorize the configured public key on the device or use --recover-ssh") from error
            else:
                from stage_srdssh_recovery import recover
                recovery = recover(udid,key,output,instance.name)
                refreshed=plistlib.loads(path.read_bytes())
                result=repair(udid,path,refreshed,identity,output)
                result["key_enrollment"]=recovery
                return result
            p = pair.ssh(base,"id -u")
        if p.stdout.strip() != b"0":
            raise RuntimeError("The authenticated device SSH session is not root")
        from sync_runtime_dependencies import sync, sync_host_worker
        namespace=worker_namespace(plistlib.loads(path.read_bytes()))
        dependencies={"device":sync(namespace),"host_worker":sync_host_worker(plistlib.loads(path.read_bytes()))}
        from sync_srd_installers import sync_host_installers
        installers=sync_host_installers(plistlib.loads(path.read_bytes()),output)
        from deploy_ipa_compression import sync_host_archive_support
        archive_support=sync_host_archive_support(plistlib.loads(path.read_bytes()),output)
        # Reuse the established HMAC marker/receipt protocol; no token leaves
        # the device and other hosts in its pairing registry are preserved.
        bridge_update = None
        bridge_hash=hashlib.sha256((HERE.parents[1]/'bridge/DeviceRuntime/trollstorelite-srd-bridge.py').read_bytes()).hexdigest()
        compatibility=pair.ssh(base,"/var/jb/usr/bin/python3 -c "+shlex.quote(
            "import hashlib;s=open('/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py','rb').read();print('ready' if hashlib.sha256(s).hexdigest()=="+repr(bridge_hash)+" else 'upgrade')"))
        if compatibility.stdout.strip()==b"upgrade":
            from update_device_bridge import update
            namespace=worker_namespace(plistlib.loads(path.read_bytes()))
            helper_program="import glob,subprocess;h=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd')+glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd');raise SystemExit(subprocess.call([h[0] if len(h)==1 else '/var/jb/usr/bin/launchctl','version'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))"
            helper=namespace['ssh']('/var/jb/usr/bin/python3 -c '+shlex.quote(helper_program),timeout=15,check=False)
            if helper.returncode:
                from install_launch_helper import install_for
                install_for(udid)
            bridge_update=update(namespace)
        with contextlib.redirect_stdout(io.StringIO()):
            paired = pair.bind_verified_relationship(udid=udid,ssh_key=key,
                host=host,port=str(port),instance_name=instance.name,support=SUPPORT,
                pairing=pairing,write_device_marker=True,require_worker=False,
                provision_wireless=False,repair_device_host_key=False,remote_port=remote_port)
        proof = None
        deadline = time.monotonic()+45
        while time.monotonic() < deadline:
            try:
                proof = pair.verify_marker(base,udid,pair.key_fingerprint(key),
                    pairing["host"]["publicKeyFingerprint"],True)
                break
            except RuntimeError:
                time.sleep(2)
        if proof is None:
            raise RuntimeError("SSH restored, but the persistent worker did not produce a verified fresh heartbeat")
        return {"profile_changed":changed,"host_key_fingerprints":fingerprints,
                "dependencies":dependencies,
                "native_installers":installers,
                "archive_support":archive_support,
                "bridge_update":bridge_update,
                "key_enrollment":recovery,
                "usb_tunnel":persistent_tunnel,
                "worker_fresh":proof["worker_fresh"],"marker_valid":proof["marker_valid"],
                "port":str(port),"interpreter":python,"persistent_worker_verified":True}
    finally:
        if temporary_tunnel is not None:
            temporary_tunnel.terminate()
            temporary_tunnel.wait(timeout=5)

def one(args):
    path,value = profiles(instance_name=args.instance_name).get(args.udid,(None,None))
    if path is None:
        raise RuntimeError("No configured worker for "+args.udid)
    env = value["EnvironmentVariables"]
    ref = hashlib.sha256(args.udid.encode()).hexdigest()[:16]
    output = args.output/ref
    output.mkdir(parents=True,mode=0o700,exist_ok=True)
    report = {"udid":args.udid,"instance_name":args.instance_name,
              "device_reference":ref,"status":"UNVERIFIED",
              "run_id":args.run_id,
              "configured_port":env.get("CRYPSTORE_DEVICE_PORT","22"),
              "host_key_pin_exists":Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"]).is_file(),
              "worker_interpreter":interpreter_status(value["ProgramArguments"][0])}
    try:
        report["device"] = asyncio.run(usb_identity(args.udid))
        if args.repair:
            report["repair"] = repair(args.udid,path,value,report["device"],output,args.recover_ssh,args.reboot_recovery,args.authorize_password)
            value = plistlib.loads(path.read_bytes())
            report["host_key_pin_exists"] = Path(value["EnvironmentVariables"]["CRYPSTORE_DEVICE_KNOWN_HOSTS"]).is_file()
            report["worker_interpreter"] = interpreter_status(value["ProgramArguments"][0])
        namespace = worker_namespace(value)
        report["ssh"] = ssh_probe(namespace)
        report["status"] = "CONNECTED" if report["ssh"]["connected"] else "FAILED"
        if args.repair and report["ssh"]["connected"]:
            from verify_device_core import check
            report["core"] = check(namespace)
            if not report["core"]["core_verified"]:
                report["status"] = "CORE_UNAVAILABLE"
    except Exception as error:
        report["status"] = "OFFLINE" if "USB_NOT_CONNECTED" in str(error) else "FAILED"
        report["error"] = str(error)[:1800]
    current = plistlib.loads(path.read_bytes())
    report["worker_interpreter"] = interpreter_status(current["ProgramArguments"][0])
    report["host_key_pin_exists"] = Path(env["CRYPSTORE_DEVICE_KNOWN_HOSTS"]).is_file()
    if report.get("repair",{}).get("profile_changed") and (output/"host-repair.json").is_file():
        report["host_repair"] = json.loads((output/"host-repair.json").read_text())
    report["checked_at"] = int(time.time())
    atomic_write(output/"connection.json",(json.dumps(report,indent=2)+"\n").encode())
    print(json.dumps(report,indent=2))
    return 0 if report["status"] == "CONNECTED" else 2

def main():
    ensure_device_python()
    parser = argparse.ArgumentParser(description=__doc__)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--udid")
    target.add_argument("--all",action="store_true",help="Process every configured worker in an isolated process")
    parser.add_argument("--instance-name",help="select one paired profile when multiple profiles share a UDID")
    parser.add_argument("--repair",action="store_true",help="Repair pins, per-device configuration, interpreter and worker binding")
    parser.add_argument("--recover-ssh",action="store_true",help="Install or reuse a corrected Apple-authorized research SSH service")
    parser.add_argument("--reboot-recovery",action="store_true",help=argparse.SUPPRESS)
    parser.add_argument("--authorize-password",action="store_true",help="Use a hidden macOS root-password dialog to authorize this Mac's public key")
    parser.add_argument("--output",type=Path,default=HERE/"connection-repair")
    parser.add_argument("--run-id",default=uuid.uuid4().hex,help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.all and args.instance_name: parser.error("--instance-name requires --udid")
    if args.recover_ssh and not args.repair: parser.error("--recover-ssh requires --repair")
    if args.authorize_password and (not args.repair or args.recover_ssh or args.all):
        parser.error("--authorize-password requires --repair and one --udid; cannot combine with --recover-ssh")
    if args.reboot_recovery:
        parser.error("Recovery now activates an isolated SSH service without reboot; omit --reboot-recovery")
    if args.udid:
        if not re.fullmatch(r"[A-Za-z0-9-]{20,80}",args.udid): parser.error("Invalid UDID")
        return one(args)
    results = []
    # Repairs are sequential: launchd, shared trust receipts and listener state
    # remain easy to audit. One failure never prevents the other devices' checks.
    instances = configured_instances()
    duplicates = {udid for udid, count in Counter(udid for udid, _ in instances).items() if count > 1}
    for udid, instance_name in instances:
        if args.repair and udid in duplicates:
            results.append({"udid":udid,"instance_name":instance_name,"status":"FAILED",
                            "error":"DUPLICATE_WORKER_PROFILE: select one exact instance before repair"})
            continue
        run_id = uuid.uuid4().hex
        command = [sys.executable,str(Path(__file__).resolve()),"--udid",udid,
                   "--instance-name",instance_name,"--output",str(args.output),"--run-id",run_id]
        if args.repair: command.append("--repair")
        if args.recover_ssh: command.append("--recover-ssh")
        try:
            p = subprocess.run(command,capture_output=True,text=True,timeout=600)
            ref = hashlib.sha256(udid.encode()).hexdigest()[:16]
            result = json.loads((args.output/ref/"connection.json").read_text())
            if result.get("run_id") != run_id or result.get("udid") != udid:
                raise ValueError("Child process did not produce a fresh report for the selected device")
            if p.returncode != (0 if result["status"] == "CONNECTED" else 2):
                raise ValueError("Child exit status disagrees with its connection report")
            results.append(result)
        except (OSError,ValueError,subprocess.TimeoutExpired) as error:
            results.append({"udid":udid,"status":"FAILED","error":str(error)[-1800:]})
    args.output.mkdir(parents=True,exist_ok=True)
    atomic_write(args.output/"devices.json",(json.dumps(results,indent=2)+"\n").encode())
    print(json.dumps(results,indent=2))
    return 0 if results and all(v["status"] == "CONNECTED" for v in results) else 2

if __name__ == "__main__":
    raise SystemExit(main())
