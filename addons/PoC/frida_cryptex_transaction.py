#!/usr/bin/env python3
"""Transactional replacement of the owned Frida trust Cryptex on one SRD."""
from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
from dataclasses import dataclass
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shlex
import sys
import time

from pymobiledevice3.remote.native_tunnel import NativeRemotedTunnel
from pymobiledevice3.remote.xpc_message import XpcUInt64Type
from pymobiledevice3.restore.tss import TSSRequest
from pymobiledevice3.services.cryptexd import CryptexdService

import frida_cryptex_rollback_preflight as backup
from frida_cryptex_transaction_core import (IDENTIFIER, TransactionFailure,
                                             replace)
from paired_frida_probe import frida_handshake
from repair_device_connection import profiles, usb_identity, worker_namespace


HERE = Path(__file__).resolve().parent
INSTALLER_SOURCE = (HERE / "srdsh-work/components/zero-sky/kit/srdssh/"
                    "install_cryptex_native.py")
FLOW_SOURCE = (HERE.parents[1] / "bridge/KitScripts/automation/"
               "CrypStoreAutomation/native-install/install_cryptex_native.py")


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("REQUIRED_INSTALLER_MODULE_MISSING")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class CryptexPayload:
    version: str
    image: bytes
    trust: bytes
    info: bytes
    volume_hash: bytes
    identity: dict
    manifest_hash: str

    async def install(self, service, ticket: bytes) -> None:
        properties = {
            "Cryptex1,UseProductClass": True,
            "MountedCryptex": False,
            "Cryptex1,SubType": XpcUInt64Type(255),
            "Cryptex1,NonceDomain": XpcUInt64Type(3),
            "Cryptex1,Version": self.identity["Cryptex1,Version"],
            "Cryptex1,PreauthVersion": self.identity["Cryptex1,PreauthorizationVersion"],
        }
        await asyncio.wait_for(service.install(
            self.image, self.trust, ticket, self.info, self.volume_hash,
            properties, image_type_index=10, persistence=2,
            nonce_persistence=1, auth=0), timeout=900)


def load_payload(directory: Path, version: str, manifest_hash: str, *,
                 allowed_roots: tuple[Path, ...]) -> CryptexPayload:
    directory = directory.resolve(strict=True)
    roots = tuple(root.resolve(strict=True) for root in allowed_roots)
    if not any(directory.is_relative_to(root) for root in roots):
        raise RuntimeError("PAYLOAD_OUTSIDE_REVIEWED_GENERATIONS")
    if any((directory / name).is_symlink() or not (directory / name).is_file()
           for name in backup.REQUIRED):
        raise RuntimeError("PAYLOAD_INCOMPLETE")
    if backup.sha256(directory / "dynamic-tweak-manifest.json") != manifest_hash:
        raise RuntimeError("PAYLOAD_MANIFEST_HASH_CHANGED")
    backup.verify_sealed_image(directory, manifest_hash)
    source = load_module(INSTALLER_SOURCE, "srdssh_identity_helpers")
    image = (directory / "srdsh-apfs-sealed-udzo.dmg").read_bytes()
    trust = (directory / "srdsh.gtcd").read_bytes()
    raw_hash = (directory / "srdsh-apfs-sealed.hash").read_bytes()
    template = plistlib.loads((directory / "BuildManifest.plist").read_bytes())
    if not image or not trust or not raw_hash:
        raise RuntimeError("PAYLOAD_ASSET_EMPTY")
    info = plistlib.dumps({"CFBundleIdentifier": IDENTIFIER,
                           "CFBundleVersion": version,
                           "DeveloperModeRequired": True},
                          fmt=plistlib.FMT_XML, sort_keys=True)
    volume_hash = source.der_sequence(
        source.der_ia5("IM4P"), source.der_ia5("gtgv"),
        source.der_ia5("0"), source.der_octets(raw_hash))
    identity = source.make_identity(template, info, trust, volume_hash, image)
    return CryptexPayload(version, image, trust, info, volume_hash,
                          identity, manifest_hash)


async def authorize(service, payload: CryptexPayload) -> bytes:
    identifiers = await asyncio.wait_for(service.read_personalization_identifiers(),
                                         timeout=30)
    nonce = await asyncio.wait_for(service.cryptex_nonce(3), timeout=30)
    if not nonce:
        raise RuntimeError("RESEARCH_NONCE_UNAVAILABLE")
    request = TSSRequest()
    request.add_cryptex1_tags(payload.identity, identifiers, nonce)
    response = await asyncio.wait_for(request.send_receive(), timeout=90)
    ticket = response.get("Cryptex1,Ticket")
    if not isinstance(ticket, (bytes, bytearray)) or not ticket:
        raise RuntimeError("APPLE_TSS_AUTHORIZATION_FAILED")
    return bytes(ticket)


async def verify_durable_registration(connect, udid: str, expected_version: str,
                                      *, settle_seconds: float = 75,
                                      sleep=asyncio.sleep,
                                      identity=usb_identity) -> None:
    """Recheck exact USB and Cryptexd after the post-install reboot window."""
    await sleep(settle_seconds)
    observed = await identity(udid)
    if observed.get("udid") != udid:
        raise RuntimeError("POST_INSTALL_USB_IDENTITY_CHANGED")
    async with connect() as service:
        entries = await asyncio.wait_for(service.copy_installed(), timeout=20)
    matches = [item.version for item in entries if item.identifier == IDENTIFIER]
    if matches != [expected_version]:
        raise RuntimeError("POST_INSTALL_CRYPTEX_NOT_DURABLE")


def remote_health(worker: dict, manifest_hash: str, *, frida: bool,
                  cleanup_orphan: bool = False) -> dict:
    code = """import hashlib,json,os,pathlib,signal,socket,subprocess,time
expected=%r
mount=subprocess.run(['/sbin/mount'],capture_output=True,text=True,timeout=5,check=True)
hashes=[]
for line in mount.stdout.splitlines():
 if 'codes.openai.research.ellekitloader' not in line:continue
 path=line.split(' on ',1)[1].split(' (',1)[0]
 p=pathlib.Path(path)/'usr/share/0-sky/dynamic-tweak-manifest.json'
 if p.is_file():hashes.append(hashlib.sha256(p.read_bytes()).hexdigest())
cat=pathlib.Path('/var/jb/Library/PreferenceLoader/Preferences/catvnc/Preferences.plist')
out={'mounted_manifest_match':hashes==[expected],
     'catvnc_descriptor_sha256':hashlib.sha256(cat.read_bytes()).hexdigest() if cat.is_file() else None}
try:
 inventory=subprocess.run(['/var/jb/usr/bin/python3',
                           '/var/jb/usr/local/libexec/crypstore-appctl.py',
                           'list','--json'],capture_output=True,text=True,timeout=10,check=True)
 tweaks=json.loads(inventory.stdout).get('tweaks',[])
 out['catvnc_settings_available']=any(t.get('package')=='com.catvnc.server' and
                                      t.get('settings_available') is True for t in tweaks)
except (OSError,ValueError,subprocess.SubprocessError):out['catvnc_settings_available']=False
if %r and out['mounted_manifest_match']:
 p=subprocess.run(['/var/jb/usr/sbin/frida-server','--version'],capture_output=True,text=True,timeout=10)
 out['frida_version']=p.stdout.strip() if p.returncode==0 else None
 if out['frida_version']=='17.18.0':
  def listening():
   try:
    s=socket.create_connection(('127.0.0.1',27042),timeout=.5);s.close();return True
   except OSError:return False
  running=False
  for _ in range(20):
   if listening():running=True;break
   time.sleep(.5)
  rows=subprocess.run(['/bin/ps','-A','-o','pid=,comm='],capture_output=True,text=True,
                      timeout=5,check=True).stdout.splitlines()
  servers=[row for row in rows if row.strip().endswith(' /var/jb/usr/sbin/frida-server')]
  out['frida_processes']=len(servers)
  out['frida_started_by_probe']=False
  if not running and not servers:
   log=open('/var/jb/var/log/frida-server.log','ab')
   try:
    subprocess.Popen(['/var/jb/usr/sbin/frida-server'],stdin=subprocess.DEVNULL,
                     stdout=log,stderr=subprocess.STDOUT,start_new_session=True,
                     close_fds=True)
    out['frida_started_by_probe']=True
   finally:log.close()
   for _ in range(20):
    if listening():running=True;break
    time.sleep(.5)
  out['frida_listener']=running
if %r and out['mounted_manifest_match']:
 rows=subprocess.run(['/bin/ps','-A','-o','pid=,comm='],capture_output=True,text=True,
                     timeout=5,check=True).stdout.splitlines()
 for row in rows:
  parts=row.strip().split(None,1)
  if len(parts)==2 and parts[0].isdigit() and parts[1]=='/var/jb/usr/sbin/frida-server':
   os.kill(int(parts[0]),signal.SIGTERM)
 time.sleep(1)
 try:
  s=socket.create_connection(('127.0.0.1',27042),timeout=2);s.close();out['orphan_frida_listener']=True
 except OSError:out['orphan_frida_listener']=False
print(json.dumps(out))
""" % (manifest_hash, frida, cleanup_orphan)
    result = worker["ssh"]("/var/jb/usr/bin/python3 -c " + shlex.quote(code),
                           timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("PINNED_SSH_HEALTH_PROBE_FAILED")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("INVALID_HEALTH_RESPONSE")
    return value


async def run(instance: str, udid: str, candidate: Path, *, apply: bool) -> dict:
    selected = profiles(instance_name=instance)
    if udid not in selected or (await usb_identity(udid))["udid"] != udid:
        raise RuntimeError("EXACT_USB_PROFILE_MISMATCH")
    worker = worker_namespace(selected[udid][1])
    instance_root = (Path(worker["INSTANCE"]) / "automation/artifacts/srd-runtime-poc/"
                     "runtime-generations")
    if instance_root.is_symlink() or not instance_root.is_dir():
        raise RuntimeError("INSTANCE_GENERATION_ROOT_UNAVAILABLE")
    allowed_roots = (instance_root, backup.GENERATIONS)
    active_hash = backup.mounted_manifest_hash(worker)
    old_version = await backup.installed_version(udid)
    old_dir = backup.select_generation(active_hash, instance_root)
    old_integrity = backup.verify_sealed_image(old_dir, active_hash)
    if candidate.is_symlink():
        raise RuntimeError("CANDIDATE_IS_SYMBOLIC_LINK")
    candidate = candidate.resolve(strict=True)
    new_manifest = json.loads((candidate / "dynamic-tweak-manifest.json").read_text())
    catvnc = [item for item in new_manifest.get("preference_descriptors", [])
              if item.get("kind") == "direct_plist" and
              item.get("package") == "com.catvnc.server"]
    if (new_manifest.get("frida", {}).get("version") != "17.18.0" or
            len(catvnc) != 1 or not isinstance(catvnc[0].get("sha256"), str)):
        raise RuntimeError("FRIDA_OR_CATVNC_CANDIDATE_INCOMPLETE")
    new_hash = backup.sha256(candidate / "dynamic-tweak-manifest.json")
    new_version = "6.0." + str(int(time.time()))
    previous = load_payload(old_dir, old_version, active_hash,
                            allowed_roots=allowed_roots)
    proposed = load_payload(candidate, new_version, new_hash,
                            allowed_roots=allowed_roots)
    observed = remote_health(worker, active_hash, frida=False)
    if (not observed.get("mounted_manifest_match") or
            observed.get("catvnc_descriptor_sha256") != catvnc[0]["sha256"] or
            observed.get("catvnc_settings_available") is not True):
        raise RuntimeError("EXISTING_CATVNC_OR_MOUNT_CHANGED")
    report = {"device_suffix": udid[-8:], "prior_version": old_version,
              "proposed_version": new_version, "prior_manifest_sha256": active_hash,
              "proposed_manifest_sha256": new_hash,
              "prior_image_sha256": old_integrity["image_sha256"],
              "candidate_generation": candidate.name,
              "mode": "APPLY" if apply else "PREFLIGHT"}
    health_observations: list[dict] = []
    flow = load_module(FLOW_SOURCE, "zero_sky_cryptex_flow")
    flow.enable_flow_control_accounting()

    @asynccontextmanager
    async def connect():
        async with NativeRemotedTunnel(serial=udid) as rsd:
            if str(rsd.udid) != udid:
                raise RuntimeError("REMOTEXPC_DEVICE_MISMATCH")
            yield CryptexdService(rsd)

    if not apply:
        async with connect() as service:
            for payload in (previous, proposed):
                await authorize(service, payload)
        report.update(result="PREFLIGHT_PASS", both_tickets_authorized=True)
        return report

    async def check_health(which: str) -> None:
        expected = proposed if which == "proposed" else previous
        last_error: BaseException | None = None
        for attempt in range(1, 4):
            observation = {"which": which, "attempt": attempt}
            health_observations.append(observation)
            try:
                value = await asyncio.to_thread(remote_health, worker,
                                                expected.manifest_hash,
                                                frida=which == "proposed",
                                                cleanup_orphan=which == "previous")
                observation["device"] = value
                if not value.get("mounted_manifest_match"):
                    raise RuntimeError("MOUNTED_MANIFEST_MISMATCH")
                if value.get("catvnc_descriptor_sha256") != catvnc[0]["sha256"]:
                    raise RuntimeError("CATVNC_DESCRIPTOR_CHANGED")
                if value.get("catvnc_settings_available") is not True:
                    raise RuntimeError("CATVNC_MENU_UNAVAILABLE")
                if which == "proposed":
                    if value.get("frida_version") != "17.18.0" or not value.get("frida_listener"):
                        raise RuntimeError("FRIDA_RUNTIME_UNHEALTHY")
                    handshake = await asyncio.to_thread(frida_handshake, udid)
                    observation["host_handshake"] = handshake
                    if handshake.get("result") != "PASS" or \
                            handshake.get("host_version") != "17.18.0":
                        raise RuntimeError("FRIDA_HOST_HANDSHAKE_FAILED")
                elif value.get("orphan_frida_listener"):
                    raise RuntimeError("ROLLBACK_LEFT_FRIDA_LISTENER")
                return
            except Exception as error:
                last_error = error
                observation["error_code"] = (
                    str(error) if isinstance(error, RuntimeError) else
                    type(error).__name__)
                await asyncio.sleep(2)
        raise RuntimeError("CRYPTEX_HEALTH_FAILED") from last_error

    async def health(which: str) -> None:
        await check_health(which)
        if which == "proposed":
            await verify_durable_registration(connect, udid, proposed.version)
            await check_health(which)

    try:
        result = await replace(connect, authorize, health,
                               previous=previous, proposed=proposed)
        report.update(result=result.status, rollback=result.rollback_status,
                      events=list(result.events),
                      health_observations=health_observations)
    except TransactionFailure as error:
        cause = error.__cause__
        code = str(cause) if isinstance(cause, RuntimeError) else ""
        if not code or not all(char.isupper() or char.isdigit() or char == "_"
                               for char in code):
            code = type(cause).__name__
        report.update(result=error.result.status,
                      rollback=error.result.rollback_status,
                      events=list(error.result.events),
                      error_code=code,
                      health_observations=health_observations)
        chain = []
        current = cause
        while current is not None and len(chain) < 8:
            item = str(current) if isinstance(current, RuntimeError) else type(current).__name__
            chain.append(item[:160])
            current = current.__cause__
        report["error_chain"] = chain
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instance")
    parser.add_argument("udid")
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    result = asyncio.run(run(args.instance, args.udid, args.candidate,
                             apply=args.apply))
    destination = HERE / "0sky-uat" / result["device_suffix"].lower() / \
        ("frida-transaction.json" if args.apply else "frida-transaction-preflight.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise RuntimeError("refusing symbolic-link transaction report")
    temporary = destination.with_name("." + destination.name + "-" + str(os.getpid()))
    with temporary.open("x") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] in ("PREFLIGHT_PASS", "INSTALLED_AND_VERIFIED") else 1


if __name__ == "__main__":
    raise SystemExit(main())
