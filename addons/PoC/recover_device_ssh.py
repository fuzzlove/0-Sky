"""Transactional public-key enrollment through Apple's research Cryptex service.

An isolated one-shot job backs up authorized_keys and restores it if the Mac
does not authenticate and commit within two minutes. Existing SSH runtimes,
host keys, private keys, and other authorized keys are never replaced.
"""
import asyncio
import copy
import hashlib
import json
from pathlib import Path
import plistlib
import shlex
import shutil
import subprocess
import time
import uuid

HERE = Path(__file__).resolve().parent
KIT = HERE / "srdsh-work/components/zero-sky/kit/srdssh"


def enrollment_script(state):
    return r'''#!/bin/sh
set -eu
: "${CRYPTEX_MOUNT_PATH:?}"
TB="$CRYPTEX_MOUNT_PATH/usr/bin/toybox"
STATE=STATE_PLACEHOLDER
DIR=/var/root/.ssh
KEYS="$DIR/authorized_keys"
umask 077
[ ! -L /var/root ] && [ ! -L "$DIR" ] && [ ! -L "$KEYS" ] || exit 78
"$TB" mkdir -p "$DIR"
"$TB" mkdir "$STATE"
if [ -e "$KEYS" ]; then
    [ -f "$KEYS" ] || exit 78
    "$TB" cp -p "$KEYS" "$STATE/before"
else
    "$TB" touch "$STATE/absent"
fi
KEY=$("$TB" cat "$CRYPTEX_MOUNT_PATH/etc/public-key")
TEMP="$DIR/.0sky-enrollment.$$"
trap '"$TB" rm -f "$TEMP"' EXIT HUP INT TERM
if [ -f "$KEYS" ]; then "$TB" cp "$KEYS" "$TEMP"; else "$TB" touch "$TEMP"; fi
if ! "$TB" grep -qxF "$KEY" "$TEMP"; then "$TB" printf '\n%s\n' "$KEY" >> "$TEMP"; fi
"$TB" chown 0:0 "$DIR" "$TEMP"
"$TB" chmod 700 "$DIR"
"$TB" chmod 600 "$TEMP"
"$TB" mv "$TEMP" "$KEYS"
"$TB" sha256sum "$KEYS" > "$STATE/enrolled.sha256"
"$TB" touch "$STATE/ready"
i=0
while [ "$i" -lt 120 ]; do
    [ ! -f "$STATE/commit" ] || exit 0
    "$TB" sleep 1
    i=$((i+1))
done
# Restore only if nobody else changed the file after enrollment.
if "$TB" sha256sum -c "$STATE/enrolled.sha256"; then
    if [ -f "$STATE/absent" ]; then
        "$TB" rm "$KEYS"
    else
        "$TB" cp -p "$STATE/before" "$TEMP"
        "$TB" mv "$TEMP" "$KEYS"
    fi
    "$TB" touch "$STATE/rolled-back"
else
    "$TB" touch "$STATE/concurrent-change"
    exit 79
fi
'''.replace("STATE_PLACEHOLDER", shlex.quote(state))


def build(output, identifier, state, key):
    from restore_srd_bootstrap import validate_srdsh_kit
    from make_cryptex import inspect_bundle
    validate_srdsh_kit(KIT)
    root = output / "root"
    (root / "usr/bin").mkdir(parents=True)
    (root / "etc").mkdir()
    (root / "Library/LaunchDaemons").mkdir(parents=True)
    for binary in ("cryptex-run", "toybox"):
        shutil.copy2(KIT / "payload-root/usr/bin" / binary, root / "usr/bin" / binary)
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", str(root / "usr/bin" / binary)], check=True, capture_output=True)
    public = subprocess.run(["/usr/bin/ssh-keygen", "-y", "-f", str(key)], check=True, capture_output=True, text=True).stdout.strip()
    if "\n" in public or not public.startswith("ssh-ed25519 "):
        raise RuntimeError("Recovery supports one valid Ed25519 public key")
    (root / "etc/public-key").write_text(public + "\n")
    (root / "usr/bin/enroll").write_text(enrollment_script(state))
    launch = {"Label":identifier, "RunAtLoad":True,
        "EnvironmentVariables":{"CRYPTEX_SHELL":"/usr/bin/sh"},
        "ProgramArguments":["/usr/bin/cryptex-run", "toybox", "sh", "-c",
            'exec "$CRYPTEX_MOUNT_PATH/usr/bin/toybox" sh "$CRYPTEX_MOUNT_PATH/usr/bin/enroll"'],
        "StandardOutPath":"/private/var/tmp/0sky-key-enrollment.log",
        "StandardErrorPath":"/private/var/tmp/0sky-key-enrollment.log"}
    (root / "Library/LaunchDaemons/enroll.plist").write_bytes(plistlib.dumps(launch))
    image = output / "source.dmg"
    subprocess.run(["hdiutil", "create", "-size", "64m", "-fs", "APFS", "-layout", "NONE",
                    "-srcfolder", str(root), "-format", "UDRW", str(image)], check=True, capture_output=True, timeout=120)
    target = output / "cryptex"
    target.mkdir()
    subprocess.run(["/System/Library/SecurityResearch/usr/bin/cryptexctl", "create",
        "--use-cryptex1-format", "--identifier", identifier, "--version", "1.0",
        "--variant", "research", "--output-directory", str(target), str(image)],
        check=True, capture_output=True, timeout=180)
    assets = inspect_bundle(next(target.glob("*.cxbd")), "research")
    (output / "assets.json").write_text(json.dumps(assets, indent=2)+"\n")
    return assets


async def install(udid, identifier, assets):
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.remote.xpc_message import XpcUInt64Type
    from pymobiledevice3.restore.tss import TSSRequest
    from pymobiledevice3.services.cryptexd import CryptexdService
    from remotexpc_flow_control import enable_flow_control_accounting
    enable_flow_control_accounting()
    data = {name:Path(path).read_bytes() for name,path in assets.items() if name.startswith("Cryptex1,")}
    identity = copy.deepcopy(plistlib.loads(Path(assets["build_manifest"]).read_bytes())["BuildIdentities"][0])
    identity.update({"Cryptex1,UseProductClass":True, "Cryptex1,ChipID":"0xff10",
        "Cryptex1,ProductClass":"0xf2", "Cryptex1,Type":3, "Cryptex1,SubType":255,
        "Cryptex1,NonceDomain":3, "Cryptex1,Version":"999.999.999.999.999,999",
        "Cryptex1,PreauthorizationVersion":"999.999.999.999.999,999"})
    for name,payload in data.items():
        identity["Manifest"][name]["Digest"] = hashlib.sha384(payload).digest()
        identity["Manifest"][name].setdefault("Info",{})["Personalize"] = True
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid: raise RuntimeError("Research transport device identity mismatch")
        service = CryptexdService(rsd)
        if any(x.identifier == identifier for x in await service.copy_installed()):
            raise RuntimeError("Recovery identifier collision")
        ids = await service.read_personalization_identifiers()
        nonce = await service.cryptex_nonce(3)
        if not nonce: raise RuntimeError("Research nonce unavailable")
        request = TSSRequest()
        request.add_cryptex1_tags(identity, ids, nonce)
        response = await asyncio.wait_for(request.send_receive(), timeout=90)
        ticket = response.get("Cryptex1,Ticket")
        if not isinstance(ticket, bytes) or not ticket: raise RuntimeError("Apple did not authorize key enrollment")
        properties = {"Cryptex1,UseProductClass":True,"MountedCryptex":False,
            "Cryptex1,SubType":XpcUInt64Type(255),"Cryptex1,NonceDomain":XpcUInt64Type(3),
            "Cryptex1,Version":identity["Cryptex1,Version"],
            "Cryptex1,PreauthVersion":identity["Cryptex1,PreauthorizationVersion"]}
        await asyncio.wait_for(service.install(data["Cryptex1,GenericDmg"],
            data["Cryptex1,GenericTrustCache"], ticket, data["Cryptex1,CryptexInfoPlist"],
            data["Cryptex1,GenericVolume"], properties, image_type_index=10,
            persistence=2, nonce_persistence=1, auth=0), timeout=900)


async def remove(udid, identifier):
    from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
    from pymobiledevice3.services.cryptexd import CryptexdService
    async with NativeRemotedTunnel(serial=udid) as rsd:
        if str(rsd.udid) != udid: raise RuntimeError("Cleanup device identity mismatch")
        service = CryptexdService(rsd)
        if any(x.identifier == identifier for x in await service.copy_installed()):
            await asyncio.wait_for(service.uninstall(identifier), timeout=30)


async def restart_device(udid):
    from pymobiledevice3.lockdown import create_using_usbmux
    from pymobiledevice3.services.diagnostics import DiagnosticsService
    async with await create_using_usbmux(serial=udid,connection_type="USB",autopair=False) as device:
        if device.udid != udid or not device.paired:
            raise RuntimeError("Restart identity verification failed")
        async with DiagnosticsService(device) as diagnostics:
            await diagnostics.restart()


def recover(udid, key, base, output, reboot=False,host=None,port=None,known_hosts=None):
    import sys
    sys.path.insert(0, str(HERE.parents[1] / "bridge/HostTools"))
    import pair
    transaction = uuid.uuid4().hex
    identifier = "com.liquidsky.key-enrollment." + transaction
    state = "/private/var/tmp/0sky-key-enrollment-" + transaction
    output = output / ("key-enrollment-" + transaction)
    output.mkdir(mode=0o700)
    report = {"udid":udid,"identifier":identifier,"device_backup":state,"committed":False}
    assets = build(output, identifier, state, key)
    attempted = False
    try:
        attempted = True
        asyncio.run(install(udid, identifier, assets))
        if reboot:
            asyncio.run(restart_device(udid))
        deadline = time.monotonic()+(120 if reboot else 45)
        while time.monotonic() < deadline:
            try:
                proof = pair.ssh(base, "id -u", timeout=15)
                if proof.stdout.strip() != b"0": raise RuntimeError("Recovery SSH is not root")
                pair.ssh(base, "test -f " + shlex.quote(state+"/ready") + " && touch " + shlex.quote(state+"/commit"))
                report["committed"] = True
                return report
            except (RuntimeError,subprocess.TimeoutExpired):
                if reboot and host is not None and port is not None and known_hosts is not None:
                    # Some older SRDssh generations rotate their volatile host
                    # key at reboot. Replacement is limited to this explicitly
                    # requested restart and another live exact-USB verification.
                    try:
                        from repair_device_connection import usb_identity
                        asyncio.run(usb_identity(udid))
                        if not pair.exact_iproxy_present(udid,str(port)):
                            raise RuntimeError("Reboot recovery tunnel identity changed")
                        previous=Path(known_hosts).read_bytes()
                        saved=output/"host-pin-before-reboot-recovery"
                        if not saved.exists():
                            saved.write_bytes(previous)
                        fingerprints=pair.ensure_device_host_key_pin(host=host,port=str(port),udid=udid,
                            known_hosts=Path(known_hosts),allow_create=False,allow_replace=True)
                        if Path(known_hosts).read_bytes()!=previous:
                            report["reboot_host_key_fingerprints"]=fingerprints
                    except Exception:
                        pass
                time.sleep(2)
        raise RuntimeError("Research enrollment did not restore client-key authentication")
    finally:
        if attempted:
            if not report["committed"]:
                # Let the one-shot job finish its automatic restoration before
                # removing its executable. No original SSH service is retired.
                for _ in range(5):
                    time.sleep(25)
        (output / "transaction.json").write_text(json.dumps(report, indent=2)+"\n")
        if attempted:
            asyncio.run(remove(udid, identifier))
