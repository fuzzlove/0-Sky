#!/usr/bin/env python3
"""Inspect and repair LocalFence on an explicitly selected, paired SRD."""
import argparse
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import time
import plistlib
import sys

from register_mounted_app import paired_ssh

HERE = Path(__file__).resolve().parent
LAUNCHKIT = HERE / "appregistrard-swiftpm/checkouts/LaunchKit"
IDENTIFIER = "com.emp0ry.localfence.srd-repair2"

def build(output):
    root = output / "payload"
    root.mkdir(exist_ok=True)
    sources = LAUNCHKIT / "Sources/CLaunchKit"
    entry = output / "launchctl_main.c"
    entry.write_text('#include "launchctl.h"\nextern char **environ;\n'
                     'int main(int argc, char **argv) { return launchctl_invoke(argc, argv, environ, 0, 0); }\n')
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"],text=True).strip()
    subprocess.run(["xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64-apple-ios18.0",
                    "-isysroot", sdk, "-fblocks", "-O2", "-I", str(sources / "include"),
                    "-I", str(sources), str(entry),
                    *[str(p) for p in sorted(sources.glob("*.c"))],
                    *[str(p) for p in sorted(sources.glob("*.m"))],
                    "-framework", "Foundation", "-o", str(root / "launchctl-srd")],
                   check=True, timeout=120)
    for name in ("localfencectl", "localfenced", "route", "arp"):
        shutil.copy2(HERE / "compatibility-work/localfence-binaries" / name, root / name)
        if name == "localfenced":
            data = (root/name).read_bytes()
            old = b"/Applications/LocalFence.app/LocalFence\0"
            new = b"/LocalFence.app/LocalFence\0"
            if data.count(old) != 1: raise ValueError("Daemon differs from the diagnosed 0.2.1 build")
            (root/name).write_bytes(data.replace(old,new+b"\0"*(len(old)-len(new))))
        subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-",
                        "--identifier", "com.emp0ry." + name, str(root / name)],check=True)
    entitlements = LAUNCHKIT / "iOS/launchctl_srd/launchctl_srd/launchctl_srd.entitlements"
    subprocess.run(["/usr/bin/codesign", "--force", "--sign", "-", "--entitlements",
                    str(entitlements), str(root / "launchctl-srd")],check=True)
    shutil.copy2(HERE / "compatibility-work/localfence-binaries/libiosexec.1.dylib",
                 root / "libiosexec.1.dylib")
    for p in root.iterdir():
        p.chmod(0o755)
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(p)],check=True)
    manifest = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.iterdir()}
    (output / "payload-sha256.json").write_text(json.dumps(manifest,indent=2)+"\n")
    print("Built and verified signed LocalFence payload and SRD launch helper",flush=True)

def build_cryptex(output, flat=False):
    root = output / "runtime-root"
    target = output / ("cryptex-flat" if flat else "cryptex-layout")
    root.mkdir(exist_ok=True)
    hashes = json.loads((output/"payload-sha256.json").read_text())
    for name,expected in hashes.items():
        if hashlib.sha256((output/"payload"/name).read_bytes()).hexdigest() != expected:
            raise RuntimeError("Signed payload changed after verification: "+name)
    if target.is_dir() and not any(target.iterdir()):
        target.rmdir()
    for name,relative in {"localfencectl":"usr/bin/localfencectl",
                          "launchctl-srd":"usr/bin/launchctl-srd",
                          "localfenced":"usr/libexec/localfence/localfenced",
                          "route":"usr/sbin/route", "arp":"usr/sbin/arp",
                          "libiosexec.1.dylib":"usr/lib/libiosexec.1.dylib"}.items():
        dest = root / relative
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(output / "payload" / name, dest)
    launch = root / "Library/LaunchDaemons/com.emp0ry.localfenced.plist"
    launch.parent.mkdir(parents=True,exist_ok=True)
    launch.write_bytes(plistlib.dumps({"Label":"com.emp0ry.localfenced",
        "ProgramArguments":["/usr/libexec/localfence/localfenced"],
        "RunAtLoad":True,"KeepAlive":True,"ThrottleInterval":5,
        "StandardOutPath":"/var/jb/var/log/localfenced.log",
        "StandardErrorPath":"/var/jb/var/log/localfenced.log"}))
    if flat:
        from make_cryptex import inspect_bundle
        image = output / "source-apfs.dmg"
        subprocess.run(["hdiutil","create","-size","384m","-fs","APFS","-layout","NONE",
                        "-srcfolder",str(root),"-format","UDRW",str(image)],check=True,timeout=120)
        target.mkdir()
        subprocess.run(["/System/Library/SecurityResearch/usr/bin/cryptexctl","create",
                        "--use-cryptex1-format","--identifier",IDENTIFIER,"--version","0.2.1.1",
                        "--variant","research","--output-directory",str(target),str(image)],check=True,timeout=180)
        bundle = next(target.glob("*.cxbd"))
        assets = inspect_bundle(bundle,"research")
        (target/"assets.json").write_text(json.dumps({"identifier":IDENTIFIER,"version":"0.2.1.1",
            "bundle":str(bundle.resolve()),"assets":assets},indent=2)+"\n")
    else:
        subprocess.run([sys.executable, str(HERE / "make_cryptex.py"), "--dstroot", str(root),
                    "--identifier", IDENTIFIER, "--version", "0.2.1.1", "--format", "cryptex1",
                    "--output", str(target)],check=True,timeout=180)
    (output / "active-build.json").write_text((target / "assets.json").read_text())

async def install_runtime(output, udid, ssh):
    """Install a new, isolated runtime; never replace an existing cryptex."""
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.remote.xpc_message import XpcUInt64Type
    from pymobiledevice3.restore.tss import TSSRequest
    from pymobiledevice3.services.cryptexd import CryptexdService
    from remotexpc_flow_control import enable_flow_control_accounting
    from make_cryptex import inspect_bundle
    enable_flow_control_accounting()
    record = json.loads((output / "active-build.json").read_text())
    assets = inspect_bundle(Path(record["bundle"]), "research")
    data = {key:Path(path).read_bytes() for key,path in assets.items() if key.startswith("Cryptex1,")}
    info = plistlib.loads(data["Cryptex1,CryptexInfoPlist"])
    if info["CFBundleIdentifier"] != IDENTIFIER:
        raise RuntimeError("Unexpected runtime identifier")
    identity = copy.deepcopy(plistlib.loads(Path(assets["build_manifest"]).read_bytes())["BuildIdentities"][0])
    identity.update({"Cryptex1,UseProductClass":True,"Cryptex1,ChipID":"0xff10",
                     "Cryptex1,ProductClass":"0xf2","Cryptex1,Type":3,"Cryptex1,SubType":255,
                     "Cryptex1,NonceDomain":3,"Cryptex1,Version":"999.999.999.999.999,999",
                     "Cryptex1,PreauthorizationVersion":"999.999.999.999.999,999"})
    for key,value in data.items():
        identity["Manifest"][key]["Digest"] = hashlib.sha384(value).digest()
        identity["Manifest"][key].setdefault("Info",{})["Personalize"] = True
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid: raise RuntimeError("Device identity mismatch")
        service = CryptexdService(rsd)
        existing = await asyncio.wait_for(service.copy_installed(),timeout=30)
        if any(item.identifier == IDENTIFIER for item in existing):
            raise RuntimeError("Repair runtime already exists; inspect the saved repair report before retrying")
        identifiers = await service.read_personalization_identifiers()
        nonce = await service.cryptex_nonce(3)
        if not nonce: raise RuntimeError("Empty research nonce")
        request = TSSRequest()
        request.add_cryptex1_tags(identity, identifiers, nonce)
        response = await request.send_receive()
        ticket = response.get("Cryptex1,Ticket")
        if not isinstance(ticket,bytes) or not ticket: raise RuntimeError("Apple did not authorize the runtime")
        print("Live Apple research authorization accepted",flush=True)
        properties = {"Cryptex1,UseProductClass":True,"MountedCryptex":False,
                      "Cryptex1,SubType":XpcUInt64Type(255),"Cryptex1,NonceDomain":XpcUInt64Type(3),
                      "Cryptex1,Version":identity["Cryptex1,Version"],
                      "Cryptex1,PreauthVersion":identity["Cryptex1,PreauthorizationVersion"]}
        try:
            await asyncio.wait_for(service.install(data["Cryptex1,GenericDmg"],
                data["Cryptex1,GenericTrustCache"],ticket,data["Cryptex1,CryptexInfoPlist"],
                data["Cryptex1,GenericVolume"],properties,image_type_index=10,
                persistence=2,nonce_persistence=1,auth=0),timeout=300)
            (output / "runtime-installed.json").write_text(json.dumps({"identifier":IDENTIFIER,"udid":udid,"authorized":True})+"\n")
            print("Isolated LocalFence research runtime installed",flush=True)
        except Exception:
            # Only this adapter's previously absent identifier may be removed.
            now = await asyncio.wait_for(service.copy_installed(),timeout=30)
            if any(item.identifier == IDENTIFIER for item in now):
                await asyncio.wait_for(service.uninstall(IDENTIFIER),timeout=30)
            raise

async def collect_logs(output,udid):
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.os_trace import OsTraceService
    lines = []
    async with await create_using_usbmux(serial=udid,autopair=False) as device:
        async with OsTraceService(device) as service:
            async def collect():
                async for entry in service.syslog():
                    if Path(entry.filename).name == "cryptexd" or "com.emp0ry" in entry.message:
                        line = str(entry.timestamp)+" "+entry.filename+" "+entry.message
                        lines.append(line)
                        if "com.emp0ry" in entry.message and any(word in entry.message.lower() for word in ("failed","succeeded","mount")):
                            print(line[:1500],flush=True)
            try:
                await asyncio.wait_for(collect(),timeout=15)
            except asyncio.TimeoutError:
                pass
    (output / "cryptex-device.log").write_text("\n".join(lines)+"\n")

async def logged_install(output,udid,ssh):
    logger = asyncio.create_task(collect_logs(output,udid))
    await asyncio.sleep(1)
    try:
        await install_runtime(output,udid,ssh)
    finally:
        await logger

async def remove_unused_runtime(output, udid):
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.services.cryptexd import CryptexdService
    original = json.loads((HERE/"localfence-repair/runtime-installed.json").read_text())
    if original != {"identifier":"com.emp0ry.localfence.srd-runtime","udid":udid,"authorized":True}:
        raise RuntimeError("Unused runtime ownership does not match this repair")
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid: raise RuntimeError("Device identity mismatch")
        await asyncio.wait_for(CryptexdService(rsd).uninstall(original["identifier"]),timeout=30)
    (output/"cleanup.json").write_text(json.dumps({"removed":original["identifier"]})+"\n")
    print("Removed the superseded diagnostic runtime")

VERIFY = r'''
import hashlib,json,os,plistlib,stat,subprocess,time
from pathlib import Path
mounts = [p for p in Path("/private/var/run/com.apple.security.cryptexd/mnt").glob("com.emp0ry.localfence.srd-repair2.*") if os.path.ismount(p)]
if len(mounts) != 1: raise RuntimeError("Repair runtime is not mounted")
root = mounts[0]
paths = {"usr/bin/localfencectl":"/var/jb/usr/bin/localfencectl",
    "usr/libexec/localfence/localfenced":"/var/jb/usr/libexec/localfence/localfenced",
    "usr/sbin/route":"/var/jb/usr/sbin/route","usr/sbin/arp":"/var/jb/usr/sbin/arp",
    "usr/lib/libiosexec.1.dylib":"/var/jb/usr/lib/libiosexec.1.dylib"}
for relative,name in paths.items():
    if hashlib.sha256(Path(name).read_bytes()).digest() != hashlib.sha256((root/relative).read_bytes()).digest():
        raise RuntimeError("Installed code differs from trusted runtime: "+name)
helper = str(root/"usr/bin/launchctl-srd")
p = subprocess.run([helper,"kickstart","-k","system/com.emp0ry.localfenced"],capture_output=True,timeout=15)
if p.returncode: raise RuntimeError("Daemon restart failed: "+p.stderr.decode(errors="replace"))
for attempt in range(20):
    p = subprocess.run(["/var/jb/usr/bin/localfencectl","status"],capture_output=True,timeout=10)
    if p.returncode == 0: break
    time.sleep(0.25)
else: raise RuntimeError("Daemon did not recover after restart")
status = json.loads(p.stdout)
if status.get("ok") is not True: raise RuntimeError("Daemon status is unhealthy")
socket = Path("/var/mobile/Library/LocalFence/localfence.sock").stat()
plist = plistlib.loads((root/"Library/LaunchDaemons/com.emp0ry.localfenced.plist").read_bytes())
print(json.dumps({"status":status,"signed_runtime_bytes_match":True,"daemon_restart":True,
    "socket":{"uid":socket.st_uid,"gid":socket.st_gid,"mode":oct(stat.S_IMODE(socket.st_mode))},
    "persistent_launch_definition":plist,"reboot_tested":False}))
'''

PROBE_RUNTIME = r'''
import json,os,subprocess
from pathlib import Path
mounts = [p for p in Path("/private/var/run/com.apple.security.cryptexd/mnt").glob("com.emp0ry.localfence.srd-repair2.*") if os.path.ismount(p)]
if len(mounts) != 1: raise RuntimeError("Expected exactly one mounted repair runtime")
root = mounts[0]
results = {"mount":str(root),"tools":{p:Path(p).exists() for p in ("/usr/sbin/route","/usr/sbin/arp","/var/jb/usr/sbin/route","/var/jb/usr/sbin/arp")}}
for label,args in {"launch_version":[str(root/"usr/bin/launchctl-srd"),"version"],
                   "service":[str(root/"usr/bin/launchctl-srd"),"print","system/com.emp0ry.localfenced"],
                   "client":[str(root/"usr/bin/localfencectl"),"status"]}.items():
    value = subprocess.run(args,capture_output=True,timeout=10)
    results[label] = {"exit":value.returncode,"stdout":value.stdout.decode(errors="replace")[:8192],"stderr":value.stderr.decode(errors="replace")[:2048]}
print(json.dumps(results))
'''

ACTIVATE = r'''
import hashlib,json,os,plistlib,shutil,subprocess,time,uuid
from pathlib import Path
mounts = [p for p in Path("/private/var/run/com.apple.security.cryptexd/mnt").glob("com.emp0ry.localfence.srd-repair2.*") if os.path.ismount(p)]
if len(mounts) != 1: raise RuntimeError("Expected exactly one mounted repair runtime")
root = mounts[0]
helper = str(root/"usr/bin/launchctl-srd")
for name,expected in expected_payload.items():
    relative = {"localfencectl":"usr/bin/localfencectl","localfenced":"usr/libexec/localfence/localfenced",
                "route":"usr/sbin/route","arp":"usr/sbin/arp","launchctl-srd":"usr/bin/launchctl-srd",
                "libiosexec.1.dylib":"usr/lib/libiosexec.1.dylib"}[name]
    if hashlib.sha256((root/relative).read_bytes()).hexdigest() != expected:
        raise RuntimeError("Mounted runtime differs from signed payload: "+name)
if hashlib.sha256(Path("/var/jb/usr/lib/libiosexec.1.dylib").read_bytes()).digest() != hashlib.sha256((root/"usr/lib/libiosexec.1.dylib").read_bytes()).digest():
    raise RuntimeError("Network library changed since collection")
service = "system/com.emp0ry.localfenced"
def command(args,check=True):
    p = subprocess.run(args,capture_output=True,timeout=15)
    value = {"exit":p.returncode,"stdout":p.stdout.decode(errors="replace")[:16384],"stderr":p.stderr.decode(errors="replace")[:4096]}
    if check and p.returncode: raise RuntimeError(json.dumps({"command":args,"result":value}))
    return value
prior = command([helper,"print",service],False)
if prior["exit"] == 0:
    command([helper,"bootout",service])
elif prior["exit"] != 113: raise RuntimeError("Unable to inspect original daemon state")
backup = Path("/var/jb/var/lib/localfence-srd/backups")/str(uuid.uuid4())
backup.mkdir(parents=True)
paths = {"usr/bin/localfencectl":"/var/jb/usr/bin/localfencectl",
         "usr/libexec/localfence/localfenced":"/var/jb/usr/libexec/localfence/localfenced",
         "usr/sbin/route":"/var/jb/usr/sbin/route","usr/sbin/arp":"/var/jb/usr/sbin/arp"}
saved = {}
for relative,name in paths.items():
    target = Path(name)
    saved[name] = hashlib.sha256(target.read_bytes()).hexdigest()
    shutil.copy2(target,backup/target.name)
(backup/"before.json").write_text(json.dumps(saved,indent=2))
loaded = False
try:
    for relative,name in paths.items():
        target = Path(name)
        if hashlib.sha256(target.read_bytes()).hexdigest() != saved[name]: raise RuntimeError("Installed file changed during repair")
        temporary = target.with_name(target.name+".srd-repair-new")
        shutil.copy2(root/relative,temporary)
        temporary.chmod(0o755)
        os.chown(temporary,0,0)
        temporary.replace(target)
    Path("/var/jb/var/log").mkdir(parents=True,exist_ok=True)
    command([helper,"bootstrap","system","/var/jb/Library/LaunchDaemons/com.emp0ry.localfenced.plist"])
    loaded = True
    result = None
    for attempt in range(20):
        result = command(["/var/jb/usr/bin/localfencectl","status"],False)
        if result["exit"] == 0: break
        time.sleep(0.25)
    if result["exit"] != 0: raise RuntimeError("Status validation failed: "+json.dumps(result))
    parsed = json.loads(result["stdout"])
    report = {"backup":str(backup),"status":parsed,"service":command([helper,"print",service]),"device_modified":True}
    (backup/"after.json").write_text(json.dumps(report,indent=2))
    print(json.dumps(report))
except Exception as e:
    if loaded: command([helper,"bootout",service],False)
    for name in saved:
        target = Path(name)
        temporary = target.with_name(target.name+".srd-rollback-new")
        shutil.copy2(backup/target.name,temporary)
        temporary.replace(target)
    (backup/"failure.txt").write_text(str(e))
    raise RuntimeError("Repair rolled back; backup "+str(backup)+": "+str(e))
'''

INSPECT = r'''
import ctypes, glob, json, os, plistlib, subprocess
from pathlib import Path
def command(args):
    try:
        p = subprocess.run(args, capture_output=True, timeout=10)
        return {"exit":p.returncode,"stdout":p.stdout.decode(errors="replace")[:8192],
                "stderr":p.stderr.decode(errors="replace")[:8192]}
    except Exception as e: return {"error":str(e)}
lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
pids = (ctypes.c_int * 4096)()
n = lib.proc_listallpids(pids, ctypes.sizeof(pids))
processes = []
for pid in list(pids)[:n]:
    buf = ctypes.create_string_buffer(4096)
    if lib.proc_pidpath(pid,buf,len(buf)) > 0:
        name = buf.value.decode(errors="replace")
        if any(t in name.lower() for t in ("registrar","localfence","rootd","launchctl","runtime")):
            processes.append({"pid":pid,"path":name})
directory = Path("/private/var/installd/Library/Caches/TrustCacheRequests")
print(json.dumps({"uid":os.getuid(),"processes":processes,
    "trust_requests_directory":directory.is_dir(),
    "trust_errors":{p.name:p.read_text(errors="replace")[:1024] for p in directory.glob("*.error")},
    "launch_tools":glob.glob("/usr/bin/*launch*")+glob.glob("/usr/sbin/*launch*"),
    "mounts":command(["/sbin/mount"]),
    "os":plistlib.loads(Path("/System/Library/CoreServices/SystemVersion.plist").read_bytes()),
    "status":command(["/var/jb/usr/bin/localfencectl","status"])}))
'''

def remote_python(ssh, code, timeout=45):
    result = ssh("/var/jb/usr/bin/python3 -c " + shlex.quote(code),
                 timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"Remote operation exited {result.returncode}: "
                           + result.stderr.decode(errors="replace")[:2048])
    return json.loads(result.stdout)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--output", type=Path, default=Path("localfence-repair-v2"))
    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--build", action="store_true")
    operation.add_argument("--build-cryptex", action="store_true")
    parser.add_argument("--flat-image", action="store_true")
    operation.add_argument("--install-runtime", action="store_true")
    operation.add_argument("--logs", action="store_true")
    operation.add_argument("--probe-runtime", action="store_true")
    operation.add_argument("--activate", action="store_true")
    operation.add_argument("--collect-network-tools", action="store_true")
    operation.add_argument("--network-probe", action="store_true")
    operation.add_argument("--verify", action="store_true")
    operation.add_argument("--remove-unused-runtime", action="store_true")
    args = parser.parse_args()
    if args.flat_image and not args.build_cryptex:
        parser.error("--flat-image requires --build-cryptex")
    args.output.mkdir(parents=True, exist_ok=True)
    if args.build:
        build(args.output)
        return
    if args.build_cryptex:
        build_cryptex(args.output,args.flat_image)
        return
    ssh = paired_ssh(args.udid)
    if args.remove_unused_runtime:
        asyncio.run(remove_unused_runtime(args.output,args.udid))
        return
    if args.verify:
        report = remote_python(ssh,VERIFY,timeout=60)
        (args.output/"verification.json").write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report,indent=2))
        return
    if args.network_probe:
        code = r'''
import json,subprocess,os,glob
result = {"libraries":glob.glob("/var/jb/usr/lib/libiosexec*")}
for name,args in {"route":["/var/jb/usr/sbin/route","-n","get","default"],"arp":["/var/jb/usr/sbin/arp","-an"],"system-arp":["/usr/sbin/arp","-an"]}.items():
    try:
        p=subprocess.run(args,capture_output=True,timeout=8)
        result[name]={"exit":p.returncode,"stdout":p.stdout.decode(errors="replace")[:2048],"stderr":p.stderr.decode(errors="replace")[:2048]}
    except Exception as e: result[name]={"error":str(e)}
print(json.dumps(result))
'''
        report = remote_python(ssh,code)
        print(json.dumps(report,indent=2))
        (args.output/"network-probe.json").write_text(json.dumps(report,indent=2)+"\n")
        return
    if args.collect_network_tools:
        root = HERE / "compatibility-work/localfence-binaries"
        for name in ("route","arp"):
            r = ssh("cat " + shlex.quote("/var/jb/usr/sbin/"+name),timeout=15)
            (root/name).write_bytes(r.stdout)
            subprocess.run(["otool","-L",str(root/name)],check=True)
            subprocess.run(["codesign","--verify","--strict",str(root/name)],check=False)
        r = ssh("cat /var/jb/usr/lib/libiosexec.1.dylib",timeout=15)
        (root/"libiosexec.1.dylib").write_bytes(r.stdout)
        subprocess.run(["otool","-L",str(root/"libiosexec.1.dylib")],check=True)
        subprocess.run(["codesign","--verify","--strict",str(root/"libiosexec.1.dylib")],check=True)
        return
    if args.activate:
        expected = json.loads((args.output/"payload-sha256.json").read_text())
        report = remote_python(ssh,"expected_payload = "+repr(expected)+"\n"+ACTIVATE,timeout=75)
        (args.output / "activation.json").write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report,indent=2))
        return
    if args.probe_runtime:
        report = remote_python(ssh, PROBE_RUNTIME)
        (args.output / "runtime-probe.json").write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps(report,indent=2))
        return
    if args.logs:
        asyncio.run(collect_logs(args.output,args.udid))
        return
    if args.install_runtime:
        asyncio.run(logged_install(args.output,args.udid,ssh))
        return
    report = remote_python(ssh, INSPECT)
    (args.output / "inspection.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report,indent=2))

if __name__ == "__main__":
    main()
