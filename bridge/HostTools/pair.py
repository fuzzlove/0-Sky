#!/usr/bin/env python3
"""Pair one Apple device with this Mac and bind its 0-Sky bridge.

The Apple Lockdown trust dialog is the authority for computer pairing.  After
Lockdown and the configured root SSH channel both succeed, this tool writes a
device-local, bridge-token-authenticated marker.  The marker contains no
credential.  A fresh Mac-worker heartbeat must match its UDID and SSH key
fingerprint before the device bridge permits privileged mutations.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time

from apple_device_pairing import MacPairingCoordinator
from apple_device_transport import AppleDeviceTransportManager

PAIRING_FILE = "/var/jb/var/lib/0-sky/pairing.json"
TOKEN_FILE = "/var/jb/etc/trollstorelite-srd-bridge.token"
PAIRING_REGISTRY_SCHEMA = 2
MAX_PAIRED_HOSTS = 16


def log(message: str) -> None:
    print(f"[0-Sky Link pairing] {message}", flush=True)


def slug(value: str) -> str:
    result = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:63]
    if not result:
        raise SystemExit("instance name/UDID is invalid")
    return result


def run(argv: list[str], *, input_data: bytes | None = None,
        timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(argv, input=input_data, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout, check=False)
    if check and completed.returncode:
        detail = (completed.stdout + completed.stderr).decode("utf-8", "replace").strip()
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(argv)}\n{detail}")
    return completed


def key_fingerprint(key: Path) -> str:
    public = run(["/usr/bin/ssh-keygen", "-y", "-f", str(key)]).stdout.decode().strip()
    fields = public.split()
    if len(fields) < 2:
        raise RuntimeError("SSH key has no valid public-key representation")
    digest = hashlib.sha256(base64.b64decode(fields[1])).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def host_name() -> str:
    completed = run(["/usr/sbin/scutil", "--get", "ComputerName"], check=False)
    return completed.stdout.decode("utf-8", "replace").strip() or socket.gethostname()


def device_host_alias(udid: str) -> str:
    """Return a privacy-preserving, stable OpenSSH host-key lookup name."""
    return "0sky-device-" + hashlib.sha256(udid.encode("utf-8")).hexdigest()[:24]


def _parse_host_keys(data: str, expected_alias: str, *,
                     canonicalize_host: bool = False) -> list[tuple[str, str, str]]:
    """Validate known-host/keyscan records and return canonical key tuples."""
    records: list[tuple[str, str, str]] = []
    allowed = {
        "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    }
    for raw in data.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3 or fields[1] not in allowed:
            raise RuntimeError("device SSH host-key data contains an unsupported record")
        try:
            decoded = base64.b64decode(fields[2], validate=True)
        except Exception as error:
            raise RuntimeError("device SSH host-key data is malformed") from error
        if len(decoded) < 32:
            raise RuntimeError("device SSH host key is unexpectedly short")
        records.append((expected_alias if canonicalize_host else fields[0],
                        fields[1], fields[2]))
    if not records:
        raise RuntimeError("device SSH service did not provide a usable host key")
    return sorted(set(records), key=lambda value: (value[1], value[2]))


def _host_key_fingerprints(records: list[tuple[str, str, str]]) -> list[str]:
    return sorted({
        "SHA256:" + base64.b64encode(
            hashlib.sha256(base64.b64decode(blob, validate=True)).digest()
        ).decode().rstrip("=")
        for _, _, blob in records
    })


def ensure_device_host_key_pin(*, host: str, port: str, udid: str,
                               known_hosts: Path, allow_create: bool,
                               allow_replace: bool = False) -> list[str]:
    """Pin the device SSH host key through the exact-UDID USB tunnel.

    Initial pin creation is deliberately limited to the loopback iproxy path
    that ``prepare_loopback_tunnel`` has already bound to the coordinator's
    exact Lockdown-verified UDID.  A LAN hostname or IP address is never a
    trust root.  Later USB or wireless connections use this same pin with
    StrictHostKeyChecking=yes.
    """
    alias = device_host_alias(udid)
    parent = known_hosts.parent
    parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if parent.is_symlink():
        raise RuntimeError("device SSH trust directory must not be a symbolic link")
    os.chmod(parent, 0o700)

    existing: list[tuple[str, str, str]] | None = None
    if known_hosts.exists():
        if known_hosts.is_symlink() or not known_hosts.is_file():
            raise RuntimeError("device SSH known-hosts path is not a regular file")
        if known_hosts.stat().st_mode & 0o077:
            raise RuntimeError("device SSH known-hosts file must have mode 0600")
        existing = _parse_host_keys(known_hosts.read_text(encoding="utf-8"), alias)
        if any(record[0] != alias for record in existing):
            raise RuntimeError("device SSH known-hosts alias does not match this device")

    loopback = host in ("127.0.0.1", "localhost", "::1")
    if existing is None and (not allow_create or not loopback):
        raise RuntimeError(
            "device SSH host key is not pinned; reconnect this device by USB and repair pairing"
        )
    if existing is not None and not loopback:
        # The strict SSH handshake below proves possession of the already
        # pinned key. Never replace it from an unauthenticated LAN scan.
        return _host_key_fingerprints(existing)

    scanner = shutil.which("ssh-keyscan") or "/usr/bin/ssh-keyscan"
    completed = run([scanner, "-T", "10", "-p", str(port), host],
                    timeout=15, check=False)
    if completed.returncode not in (0, 1):
        raise RuntimeError("unable to read the device SSH host key over the verified USB tunnel")
    scanned = _parse_host_keys(completed.stdout.decode("utf-8", "strict"), alias,
                               canonicalize_host=True)
    if existing is not None:
        pinned = {(key_type, blob) for _, key_type, blob in existing}
        offered = {(key_type, blob) for _, key_type, blob in scanned}
        if not pinned.intersection(offered):
            if not allow_replace:
                raise RuntimeError(
                    "DEVICE_HOST_KEY_MISMATCH: reconnect by USB and explicitly repair device trust"
                )
            # Replacement is permitted only on this loopback path, after
            # prepare_loopback_tunnel proved that the listener is an iproxy
            # bound to the exact Lockdown-verified UDID.  Never rotate a pin
            # from a LAN hostname or an unbound local listener.
            existing = None
        else:
            return _host_key_fingerprints(existing)

    encoded = "".join(f"{alias} {key_type} {blob}\n"
                      for _, key_type, blob in scanned).encode("utf-8")
    temporary = parent / f".{known_hosts.name}.{os.getpid()}.{time.time_ns()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
    finally:
        os.close(descriptor)
    os.replace(temporary, known_hosts)
    os.chmod(known_hosts, 0o600)
    return _host_key_fingerprints(scanned)


def ssh_base(host: str, port: str, key: Path, *, known_hosts: Path,
             host_alias: str) -> list[str]:
    if '"' in str(known_hosts) or "\n" in str(known_hosts):
        raise RuntimeError("device SSH known-hosts path contains unsupported characters")
    return ["/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "StrictHostKeyChecking=yes",
            # ssh tokenizes each -o value internally; quote paths containing
            # spaces even though subprocess already passes one argv element.
            "-o", f'UserKnownHostsFile="{known_hosts}"',
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", f"HostKeyAlias={host_alias}",
            "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-i", str(key), "-p", str(port), f"root@{host}"]


def ssh(base: list[str], command: str, *, data: bytes | None = None,
        timeout: int = 45) -> subprocess.CompletedProcess[bytes]:
    return run(base + [command], input_data=data, timeout=timeout)


def tcp_open(host: str, port: str) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=1):
            return True
    except OSError:
        return False


def exact_iproxy_present(udid: str, port: str) -> bool:
    processes = run(["/bin/ps", "-axo", "command="], check=False).stdout.decode()
    for line in processes.splitlines():
        if udid not in line:
            continue
        if "iproxy" in line and f"{port}:22" in line:
            return True
        if ("pymobiledevice3" in line and "usbmux" in line
                and "forward" in line and "--serial" in line
                and f"forward {port} 22" in line):
            return True
        # iOS 27 CoreDevice may expose the authenticated developer SSH
        # endpoint through the installed per-connection forwarder rather than
        # usbmuxd.  The listener remains loopback-only and its wrapper receives
        # one exact UDID, preserving the same binding required above.
        fields = line.split()
        if ("ncat" in line and "coredevice_ssh_forward.sh" in line
                and "127.0.0.1" in fields and str(port) in fields
                and udid in fields):
            return True
    return False


def prepare_loopback_tunnel(host: str, port: str, udid: str) -> subprocess.Popen | None:
    if host not in ("127.0.0.1", "localhost", "::1"):
        return None
    if tcp_open(host, port):
        if not exact_iproxy_present(udid, port):
            raise RuntimeError(f"loopback port {port} is occupied by a tunnel that is not "
                               f"visibly bound to the requested UDID {udid}")
        return None
    iproxy = shutil.which("iproxy")
    if not iproxy:
        raise RuntimeError("iproxy is required to create the exact-UDID USB SSH tunnel")
    log(f"starting a temporary USB tunnel for {udid} on localhost:{port}")
    # libusbmuxd iproxy otherwise listens on every interface.  This channel is
    # an implementation detail of the local bridge and must never be exposed
    # to untrusted LAN clients.
    process = subprocess.Popen([iproxy, "-s", "127.0.0.1", "-u", udid, f"{port}:22"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(20):
        if process.poll() is not None:
            raise RuntimeError("iproxy could not bind the selected device/port")
        if tcp_open(host, port):
            return process
        time.sleep(.25)
    process.terminate()
    raise RuntimeError("timed out starting the exact-UDID USB SSH tunnel")


def write_marker(base: list[str], payload: dict) -> None:
    # The token never crosses the SSH channel. Device-side Python authenticates
    # and atomically merges this Mac into a bounded multi-host registry. A new
    # Mac never replaces an existing authorized Mac implicitly.
    program = r'''import hashlib,hmac,json,os,sys,time
token=open("/var/jb/etc/trollstorelite-srd-bridge.token","rb").read().strip()
if len(token)<16: raise SystemExit("privileged bridge token is missing or invalid")
bridge_path="/var/jb/usr/local/libexec/trollstorelite-srd-bridge.py"
try: bridge_source=open(bridge_path,encoding="utf-8").read(512*1024)
except OSError: raise SystemExit("Runtime Manager 2.4.10 or later is required; run Set Up iOS Components first")
if "PAIRING_REGISTRY_SCHEMA = 2" not in bridge_source:
 raise SystemExit("Runtime Manager 2.4.10 or later is required; run Set Up iOS Components first")
body=json.load(sys.stdin)
path="/var/jb/var/lib/0-sky/pairing.json"
required=("device_udid","host_key_fingerprint","mac_identity_fingerprint")
if body.get("schema")!=1 or not all(isinstance(body.get(k),str) and body[k] for k in required):
 raise SystemExit("new host pairing marker is malformed")
def host_id(value):
 raw=(value["host_key_fingerprint"]+"\0"+value["mac_identity_fingerprint"]).encode()
 return hashlib.sha256(raw).hexdigest()[:32]
def authenticated(value):
 if not isinstance(value,dict): return None
 candidate=dict(value); supplied=str(candidate.pop("hmac_sha256",""))
 canonical=json.dumps(candidate,sort_keys=True,separators=(",",":")).encode()
 return candidate if hmac.compare_digest(supplied,hmac.new(token,canonical,hashlib.sha256).hexdigest()) else None
registry={"schema":2,"device_udid":body["device_udid"],"hosts":{}}
if os.path.exists(path):
 current=authenticated(json.load(open(path,encoding="utf-8")))
 if current is None: raise SystemExit("existing pairing registry authentication failed")
 if current.get("device_udid")!=body["device_udid"]:
  raise SystemExit("existing pairing registry belongs to a different device")
 if current.get("schema")==1:
  if all(isinstance(current.get(k),str) and current[k] for k in required):
   registry["hosts"][host_id(current)]=current
  else: raise SystemExit("legacy pairing marker is incomplete")
 elif current.get("schema")==2 and isinstance(current.get("hosts"),dict):
  for key,value in current["hosts"].items():
   if (not isinstance(key,str) or len(key)!=32 or not isinstance(value,dict)
       or value.get("device_udid")!=body["device_udid"]
       or host_id(value)!=key):
    raise SystemExit("existing pairing registry contains an invalid host entry")
  registry["hosts"].update(current["hosts"])
 else: raise SystemExit("unsupported pairing registry schema")
identifier=host_id(body)
registry["hosts"][identifier]=body
if len(registry["hosts"])>16: raise SystemExit("paired Mac limit reached (16)")
canonical=json.dumps(registry,sort_keys=True,separators=(",",":")).encode()
registry["hmac_sha256"]=hmac.new(token,canonical,hashlib.sha256).hexdigest()
os.makedirs(os.path.dirname(path),mode=0o755,exist_ok=True)
temporary=path+".%d.%d.tmp"%(os.getpid(),time.time_ns())
flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
if hasattr(os,"O_NOFOLLOW"): flags|=os.O_NOFOLLOW
descriptor=os.open(temporary,flags,0o600)
try:
 with os.fdopen(descriptor,"w",encoding="utf-8") as handle:
  json.dump(registry,handle,sort_keys=True,separators=(",",":"));handle.write("\n")
  handle.flush();os.fsync(handle.fileno())
 os.chown(temporary,0,0);os.replace(temporary,path);os.chmod(path,0o600)
except Exception:
 try: os.unlink(temporary)
 except OSError: pass
 raise
print(json.dumps({"written":path,"schema":2,"device_udid":body["device_udid"],
 "active_host_id":identifier,"paired_host_count":len(registry["hosts"])}))'''
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    ssh(base, "/var/jb/usr/bin/python3 -c " + shlex.quote(program), data=encoded)


def verify_marker(base: list[str], udid: str, fingerprint: str,
                  mac_identity_fingerprint: str,
                  require_worker: bool) -> dict:
    program = r'''import hashlib,hmac,json,os,sys,time
path="/var/jb/var/lib/0-sky/pairing.json"
token=open("/var/jb/etc/trollstorelite-srd-bridge.token","rb").read().strip()
value=json.load(open(path,encoding="utf-8")); candidate=dict(value)
tag=str(candidate.pop("hmac_sha256",""))
canonical=json.dumps(candidate,sort_keys=True,separators=(",",":")).encode()
valid=hmac.compare_digest(tag,hmac.new(token,canonical,hashlib.sha256).hexdigest())
requested_host_key=sys.argv[1];requested_mac_identity=sys.argv[2]
def host_id(marker):
 raw=(marker.get("host_key_fingerprint","")+"\0"+marker.get("mac_identity_fingerprint","")).encode()
 return hashlib.sha256(raw).hexdigest()[:32]
paired_host_count=1 if candidate.get("schema")==1 else 0
active_host_id=None
if valid and candidate.get("schema")==2 and isinstance(candidate.get("hosts"),dict):
 paired_host_count=len(candidate["hosts"])
 active_host_id=hashlib.sha256((requested_host_key+"\0"+requested_mac_identity).encode()).hexdigest()[:32]
 selected=candidate["hosts"].get(active_host_id)
 if not isinstance(selected,dict): valid=False;selected={}
 value=selected
elif valid and candidate.get("schema")==1:
 value=candidate;active_host_id=host_id(value)
else: valid=False;value={}
worker={}
try: worker=json.load(open("/var/jb/var/run/crypstore-worker.json",encoding="utf-8"))
except Exception: pass
fresh=max(0,int(time.time())-int(worker.get("timestamp",0)))<=15
result={"marker_valid":valid,"device_udid":value.get("device_udid"),
 "host_key_fingerprint":value.get("host_key_fingerprint"),
 "mac_identity_fingerprint":value.get("mac_identity_fingerprint"),"worker_fresh":fresh,
 "worker_udid":worker.get("device_udid"),"worker_host_key_fingerprint":worker.get("host_key_fingerprint"),
 "pairing_registry_schema":candidate.get("schema"),"paired_host_count":paired_host_count,
 "active_host_id":active_host_id}
print(json.dumps(result,separators=(",",":")))'''
    command = ("/var/jb/usr/bin/python3 -c " + shlex.quote(program) + " " +
               shlex.quote(fingerprint) + " " + shlex.quote(mac_identity_fingerprint))
    result = json.loads(ssh(base, command).stdout)
    failures = []
    if not result.get("marker_valid"): failures.append("device marker HMAC is invalid")
    if result.get("device_udid") != udid: failures.append("marker UDID does not match")
    if result.get("host_key_fingerprint") != fingerprint: failures.append("marker host key does not match")
    if result.get("mac_identity_fingerprint") != mac_identity_fingerprint:
        failures.append("marker 0-Sky Mac identity does not match")
    if require_worker:
        if not result.get("worker_fresh"): failures.append("Mac worker heartbeat is not fresh")
        if result.get("worker_udid") != udid: failures.append("worker heartbeat UDID does not match")
        if result.get("worker_host_key_fingerprint") != fingerprint:
            failures.append("worker heartbeat host key does not match")
    if failures:
        raise RuntimeError("; ".join(failures))
    return result


def bind_verified_relationship(*, udid: str, ssh_key: Path, host: str,
                               port: str, instance_name: str | None,
                               support: Path, pairing: dict,
                               write_device_marker: bool = True,
                               require_worker: bool = False,
                               provision_wireless: bool = True,
                               repair_device_host_key: bool = False) -> dict:
    """Bind a coordinator-verified Apple session to the 0-Sky device bridge.

    This callable lets the persistent Mac worker complete enrollment without
    spawning another Python interpreter or repeating Apple pairing.
    """
    if pairing.get("status") != "verified":
        raise RuntimeError("refusing to bind an unverified Apple pairing result")
    key = ssh_key.expanduser().resolve()
    if not key.is_file() or key.stat().st_mode & 0o077:
        raise RuntimeError("SSH key is missing or too broadly accessible (required mode: 0600)")
    support = support.expanduser().resolve()
    info = pairing["device"]
    if info.get("udid") != udid:
        raise RuntimeError("DEVICE_IDENTITY_MISMATCH: coordinator result changed targets")
    mac_identity_fingerprint = pairing["host"]["publicKeyFingerprint"]
    log(f"Apple trusted session verified for {info.get('platform', 'device')} "
        f"{info.get('productType', '')} {info.get('productVersion', '')}".strip())
    instance = slug(instance_name or udid)
    state_dir = support / "instances" / instance
    state_dir.mkdir(parents=True, mode=0o700, exist_ok=True)
    if state_dir.is_symlink():
        raise RuntimeError("device instance directory must not be a symbolic link")
    wireless = {"status": "not-requested"}
    if provision_wireless:
        wireless = asyncio.run(AppleDeviceTransportManager(support).enable_wireless(
            udid, mac_identity_fingerprint, usb_trust_verified=True))
        if wireless.get("status") == "ready":
            log("wireless Lockdown was enabled, rediscovered, and identity-verified")
        else:
            log(f"wireless setup incomplete: {wireless.get('errorCode', 'unsupported')}")
    else:
        # A USB-only verification must not erase an independently proven Wi-Fi
        # relationship. Preserve only the non-secret wireless object for this
        # exact instance; the transport registry remains authoritative.
        previous_state = state_dir / "pairing-state.json"
        try:
            previous = json.loads(previous_state.read_text())
            candidate = previous.get("wireless")
            if isinstance(candidate, dict):
                wireless = candidate
        except (OSError, ValueError, TypeError):
            pass
    os.chmod(state_dir, 0o700)
    known_hosts = state_dir / "device-known-hosts"
    temporary_iproxy = prepare_loopback_tunnel(host, port, udid)
    try:
        device_host_key_fingerprints = ensure_device_host_key_pin(
            host=host, port=port, udid=udid, known_hosts=known_hosts,
            allow_create=write_device_marker,
            allow_replace=repair_device_host_key)
        base = ssh_base(host, port, key, known_hosts=known_hosts,
                        host_alias=device_host_alias(udid))
        fingerprint = key_fingerprint(key)
    except Exception:
        if temporary_iproxy is not None:
            temporary_iproxy.terminate()
            try: temporary_iproxy.wait(timeout=3)
            except subprocess.TimeoutExpired: temporary_iproxy.kill()
        raise
    marker = {
        "schema": 1, "device_udid": udid, "instance_name": instance,
        "host_key_fingerprint": fingerprint,
        "device_host_key_fingerprints": device_host_key_fingerprints,
        "mac_identity_fingerprint": mac_identity_fingerprint,
        "ssh_port": str(port), "paired_at": int(time.time()),
        "pairing_method": "apple-lockdown+root-ssh+device-token-hmac",
    }
    try:
        proof = ssh(base, "test \"$(id -u)\" = 0 && test -s " + shlex.quote(TOKEN_FILE) +
                    " && printf 'root-bridge-ready\\n'")
        if proof.stdout.strip() != b"root-bridge-ready":
            raise RuntimeError("the exact device's privileged SSH bridge is not ready")
        if write_device_marker:
            write_marker(base, marker)
        device_proof = verify_marker(
            base, udid, fingerprint, mac_identity_fingerprint, require_worker)
    finally:
        if temporary_iproxy is not None:
            temporary_iproxy.terminate()
            try: temporary_iproxy.wait(timeout=3)
            except subprocess.TimeoutExpired: temporary_iproxy.kill()

    state = {
        **marker, "device_class": info.get("platform"),
        "product_type": info.get("productType"),
        "product_version": info.get("productVersion"),
        "build_version": info.get("buildVersion"),
        "applePairingEstablished": pairing["pairing"]["applePairingEstablished"],
        "lockdownSessionValidated": pairing["pairing"]["lockdownSessionValidated"],
        "expectedUDIDMatched": pairing["pairing"]["expectedUDIDMatched"],
        "hostIdentityMatched": pairing["host"]["identityVerified"],
        "transportValidated": pairing["pairing"]["transportValidated"],
        "lastVerifiedAt": pairing["pairing"]["lastVerifiedAt"],
        "research_class": pairing["researchClass"], "wireless": wireless,
        "verified": True, "worker_verified": bool(require_worker),
        "paired_host_count": int(device_proof.get("paired_host_count", 1)),
        "pairing_registry_schema": int(device_proof.get("pairing_registry_schema", 1)),
    }
    path = state_dir / "pairing-state.json"
    temporary = path.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600); temporary.replace(path)
    log(f"PAIRED: {udid} is bound to {host_name()} ({fingerprint})")
    log(f"non-secret pairing receipt: {path}")
    if require_worker:
        log("privileged bridge and exact-UDID Mac worker are both verified")
    return state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--ssh-key", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="2222")
    parser.add_argument("--instance-name")
    parser.add_argument("--support", type=Path,
                        default=Path.home() / "Library/Application Support/0-Sky")
    parser.add_argument("--pymobile-python", type=Path, default=Path(sys.executable))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify-only", action="store_true",
                      help="fail instead of showing/initiating Apple's Trust dialog")
    mode.add_argument("--confirm-host-enrollment", action="store_true",
                      help="explicitly authorize Apple pairing and first-time 0-Sky host enrollment")
    mode.add_argument("--repair-device-host-key", action="store_true",
                      help="over exact-UDID USB only, replace a rotated device SSH host-key pin")
    parser.add_argument("--require-worker", action="store_true",
                        help="also require a fresh exact-UDID Mac-worker heartbeat")
    parser.add_argument("--skip-wireless", action="store_true",
                        help="advanced diagnostics only: do not provision wireless Lockdown")
    args = parser.parse_args()

    if sys.platform != "darwin":
        raise SystemExit("pairing requires macOS and Apple's Lockdown transport")
    key = args.ssh_key.expanduser().resolve()
    if not key.is_file() or key.stat().st_mode & 0o077:
        raise SystemExit("SSH key is missing or too broadly accessible (required mode: 0600)")
    python = args.pymobile_python.expanduser().resolve()
    if not python.is_file():
        raise SystemExit(f"pymobiledevice3 Python is missing: {python}")

    coordinator = MacPairingCoordinator(args.support, timeout=300)
    pairing = asyncio.run(coordinator.run(
        args.udid,
        allow_pair=args.confirm_host_enrollment,
        allow_host_enrollment=args.confirm_host_enrollment,
    ))
    if pairing.get("status") != "verified":
        raise RuntimeError(
            f"{pairing.get('errorCode', 'VERIFICATION_FAILED')}: "
            f"{pairing.get('userMessage', 'Apple pairing failed')} "
            f"{pairing.get('safeRemediation', '')}"
        )
    bind_verified_relationship(
        udid=args.udid, ssh_key=key, host=args.host, port=str(args.port),
        instance_name=args.instance_name, support=args.support, pairing=pairing,
        write_device_marker=(args.confirm_host_enrollment or
                             args.repair_device_host_key),
        require_worker=args.require_worker,
        provision_wireless=not args.skip_wireless and args.confirm_host_enrollment,
        repair_device_host_key=args.repair_device_host_key)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(f"[0-Sky Link pairing] FAILED: {error}", file=sys.stderr)
        raise SystemExit(2)
