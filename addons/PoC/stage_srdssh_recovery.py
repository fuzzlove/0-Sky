#!/usr/bin/env python3
"""Stage an isolated, Apple-authorized SSH recovery service with an owned key."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import time
import uuid

from device_python import ensure_device_python
from make_cryptex import inspect_bundle
from recover_device_ssh import install,remove,KIT,HERE
from repair_device_connection import profiles,usb_identity,atomic_write
from restore_srd_bootstrap import validate_srdsh_kit

RECOVERY_REMOTE_PORT = 22024


def recovery_identifier(udid):
    return ("com.liquidsky.srdssh.recovery3-" +
            hashlib.sha256(udid.encode()).hexdigest()[:16])


def build(output,udid,key):
    validate_srdsh_kit(KIT)
    identifier=recovery_identifier(udid)
    root=output/"root"
    shutil.copytree(KIT/"payload-root",root)
    dropbear=root/"usr/bin/dropbear"
    shutil.copy2(HERE/"srdsh-work/srdsh/vendor/dropbear/dropbear",dropbear)
    subprocess.run(["/usr/bin/codesign","--force","--sign","-","--entitlements",
        str(HERE/"srdsh-work/srdsh/apps/dropbear/entitlements.plist"),str(dropbear)],check=True,capture_output=True)
    for name in ("dropbear","dropbearkey","toybox","cryptex-run"):
        subprocess.run(["/usr/bin/codesign","--verify","--strict",str(root/"usr/bin"/name)],check=True,capture_output=True)
    public=subprocess.run(["/usr/bin/ssh-keygen","-y","-f",str(key)],check=True,capture_output=True).stdout
    atomic_write(root/"etc/srdsh_authorized_key",public)
    startup=root/"usr/bin/srdsh-dropbear-start"
    code=startup.read_text()
    marker='-r "$HOST_KEY" -F'
    if code.count(marker)!=1: raise RuntimeError("Unexpected upstream Dropbear startup script")
    startup.write_text(code.replace(marker,marker+f" -p {RECOVERY_REMOTE_PORT}"))
    for path in (root/"Library/LaunchDaemons").glob("*.plist"):
        path.unlink()
    launch=plistlib.loads((KIT/"payload-root/Library/LaunchDaemons/dropbear.plist").read_bytes())
    launch.update(
        Label=identifier+".dropbear", RunAtLoad=True,
        ProgramArguments=[
            "/usr/bin/cryptex-run", "dropbear", "-r",
            "/private/var/db/com.liquidsky.srdssh/dropbear-ed25519-host-key",
            "-F", "-p", str(RECOVERY_REMOTE_PORT),
        ])
    (root/"Library/LaunchDaemons/dropbear.plist").write_bytes(plistlib.dumps(launch))
    image=output/"source.dmg"
    subprocess.run(["hdiutil","create","-size","64m","-fs","APFS","-layout","NONE",
        "-srcfolder",str(root),"-format","UDRW",str(image)],check=True,capture_output=True,timeout=120)
    target=output/"cryptex";target.mkdir()
    tool="/System/Library/SecurityResearch/usr/bin/cryptexctl"
    subprocess.run([tool,"create","--use-cryptex1-format","--identifier",identifier,"--version","1.2.6",
        "--variant","research","--output-directory",str(target),str(image)],check=True,capture_output=True,timeout=180)
    bundle=next(target.glob("*.cxbd"))
    assets=inspect_bundle(bundle,"research")
    # Preserve the verified Procursus trust entries used by the existing
    # bootstrap, while adding the corrected signed SSH executable.
    import sys
    sys.path.insert(0,str(KIT))
    import rekey_image
    trust=output/"combined.trustcache"
    subprocess.run([tool,"generate-trust-cache","-o",str(trust),"-t","loadable",
        "-b",str(KIT/"procursus.trustcache"),str(root)],check=True,capture_output=True,timeout=60)
    payload=rekey_image.unwrap_last_octet_string(trust.read_bytes())
    gtcd=rekey_image.der_sequence(rekey_image.der_ia5("IM4P"),rekey_image.der_ia5("gtcd"),
        rekey_image.der_ia5("1"),rekey_image.der_octets(payload))
    Path(assets["Cryptex1,GenericTrustCache"]).write_bytes(gtcd)
    manifest=plistlib.loads(Path(assets["build_manifest"]).read_bytes())
    for identity in manifest["BuildIdentities"]:
        if identity.get("Info",{}).get("Variant")=="research":
            identity["Manifest"]["Cryptex1,GenericTrustCache"]["Digest"]=hashlib.sha384(gtcd).digest()
    Path(assets["build_manifest"]).write_bytes(plistlib.dumps(manifest))
    assets=inspect_bundle(bundle,"research")
    record={"udid":udid,"identifier":identifier,"version":"1.2.6",
        "remote_port":RECOVERY_REMOTE_PORT,"assets":assets,
        "dropbear_sha256":hashlib.sha256(dropbear.read_bytes()).hexdigest(),
        "source_sha256":hashlib.sha256((HERE/"srdsh-work/srdsh/vendor/dropbear/src/svr-authpubkey.c").read_bytes()).hexdigest()}
    atomic_write(output/"recovery.json",(json.dumps(record,indent=2)+"\n").encode())
    return record


async def port_open(udid, remote_port=RECOVERY_REMOTE_PORT):
    from pymobiledevice3.usbmux import select_device
    device=await select_device(udid=udid,connection_type="USB")
    if device is None or device.serial!=udid: return False
    try: sock=await asyncio.wait_for(device.connect(remote_port),timeout=5)
    except Exception: return False
    sock.close();return True


async def recovery_installed(udid, identifier):
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.services.cryptexd import CryptexdService
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid:
            raise RuntimeError("Recovery Cryptex discovery selected another device")
        return any(item.identifier == identifier
                   for item in await CryptexdService(rsd).copy_installed())


def await_existing_recovery(udid, identifier, timeout=90):
    """Give an installed recovery service time to start after an SRD reboot."""
    if not asyncio.run(recovery_installed(udid, identifier)):
        return False
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if asyncio.run(port_open(udid)):
            return True
        time.sleep(2)
    raise RuntimeError("Installed recovery SSH Cryptex did not open its port after reboot")


def recover(udid,key,output,instance_name=None):
    """Recover sealed-key lookup failures without replacing the original service."""
    from recovery_ssh import channel
    from configure_recovery_route import configure
    asyncio.run(usb_identity(udid))
    identifier=recovery_identifier(udid)
    record={"udid":udid,"identifier":identifier,
            "remote_port":RECOVERY_REMOTE_PORT,"reused":True}
    service_ready=False
    if asyncio.run(port_open(udid)):
        try:
            with channel(udid,instance_name,RECOVERY_REMOTE_PORT) as ssh:
                service_ready=ssh("id -u",timeout=15).stdout.strip()==b"0"
        except (OSError,RuntimeError,subprocess.SubprocessError):
            service_ready=False
        if not service_ready and asyncio.run(recovery_installed(udid,identifier)):
            # A TCP listener without a complete SSH banner is not a usable
            # recovery service. Replace only this exact recovery Cryptex; the
            # primary SSH service and device data remain untouched.
            asyncio.run(remove(udid,identifier))
            record["replaced_unresponsive_service"]=True
    if not service_ready:
        if await_existing_recovery(udid,identifier):
            record["existing_service_started_after_reboot"]=True
        else:
            destination=output/("ssh-service-"+uuid.uuid4().hex)
            destination.mkdir(mode=0o700)
            record=build(destination,udid,key)
            asyncio.run(install(udid,record["identifier"],record["assets"]))
            record["installed"]=True
            deadline=time.monotonic()+20
            while time.monotonic()<deadline and not asyncio.run(port_open(udid)):
                time.sleep(1)
            atomic_write(destination/"recovery.json",(json.dumps(record,indent=2)+"\n").encode())
    # The existing device host-key pin and owned private key must prove the
    # new service before any persistent Mac route is changed.
    with channel(udid,instance_name,RECOVERY_REMOTE_PORT) as ssh:
        if ssh("id -u").stdout.strip()!=b"0":raise RuntimeError("Recovery service is not root")
    record["route"]=configure(udid,instance_name,RECOVERY_REMOTE_PORT)
    return record


def main():
    ensure_device_python()
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid",required=True)
    parser.add_argument("--instance-name")
    parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--install",action="store_true")
    args=parser.parse_args()
    asyncio.run(usb_identity(args.udid))
    _,value=profiles(instance_name=args.instance_name)[args.udid]
    key=Path(value["EnvironmentVariables"]["CRYPSTORE_DEVICE_KEY"])
    if not key.is_file() or key.stat().st_mode & 0o077: raise RuntimeError("Private-key permissions are invalid")
    args.output.mkdir(parents=True,mode=0o700)
    record=build(args.output,args.udid,key)
    if args.install:
        if asyncio.run(port_open(args.udid)): raise RuntimeError("Recovery port is already occupied")
        try: asyncio.run(install(args.udid,record["identifier"],record["assets"]))
        except Exception:
            asyncio.run(remove(args.udid,record["identifier"]))
            raise
        record["installed"]=True
        deadline=time.monotonic()+20
        while time.monotonic()<deadline and not asyncio.run(port_open(args.udid)):
            time.sleep(1)
        record["port_open"]=asyncio.run(port_open(args.udid))
        atomic_write(args.output/"recovery.json",(json.dumps(record,indent=2)+"\n").encode())
    print(json.dumps(record,indent=2))


if __name__=="__main__": main()
