#!/usr/bin/env python3
"""Exchange public-only requests for additional authorized 0-Sky Macs.

A new Mac exports a signed request for one exact device. An already authorized
Mac reviews that file and, after explicit user confirmation, appends only the
new Mac's public SSH key to the selected device. No private key, Apple pairing
record, bridge token, or credential is exported.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import uuid

from apple_device_pairing import MacIdentity

REQUEST_TYPE = "0-sky-additional-mac-pairing-request"
REQUEST_SCHEMA = 1
MAX_AUTHORIZED_MACS = 16
MAX_REQUEST_BYTES = 64 * 1024
UDID_RE = re.compile(r"^[A-Za-z0-9-]{20,80}$")
PUBLIC_KEY_RE = re.compile(
    r"(ssh-ed25519|ecdsa-sha2-nistp(?:256|384|521)|ssh-rsa) "
    r"([A-Za-z0-9+/=]+)(?: [^\r\n]+)?"
)


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def public_key_fingerprint(public_key: str) -> str:
    match = PUBLIC_KEY_RE.fullmatch(public_key.strip())
    if not match:
        raise RuntimeError("the SSH public key format is unsupported")
    decoded = base64.b64decode(match.group(2), validate=True)
    if len(decoded) < 32:
        raise RuntimeError("the SSH public key is unexpectedly short")
    digest = hashlib.sha256(decoded).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def derive_ssh_public_key(identity: Path) -> str:
    identity = identity.expanduser().resolve()
    if not identity.is_file() or identity.stat().st_mode & 0o077:
        raise RuntimeError("the 0-Sky SSH identity is missing or is not mode 0600")
    result = subprocess.run(
        ["/usr/bin/ssh-keygen", "-y", "-f", str(identity)], check=True,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    fields = result.stdout.strip().split()
    if len(fields) < 2:
        raise RuntimeError("ssh-keygen did not return a public key")
    return f"{fields[0]} {fields[1]} 0-Sky-additional-Mac"


def target_hash(udid: str) -> str:
    if not UDID_RE.fullmatch(udid):
        raise RuntimeError("the selected device identifier is invalid")
    return hashlib.sha256(udid.encode()).hexdigest()


def export_request(*, udid: str, identity: Path, support: Path,
                   destination: Path, lifetime_hours: int = 168) -> dict:
    from cryptography.hazmat.primitives import serialization

    if not 1 <= lifetime_hours <= 720:
        raise RuntimeError("request lifetime must be between 1 and 720 hours")
    ssh_public_key = derive_ssh_public_key(identity)
    mac_key, mac_fingerprint = MacIdentity(support.expanduser().resolve()).ensure()
    mac_public = mac_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    now = int(time.time())
    body = {
        "schema": REQUEST_SCHEMA,
        "type": REQUEST_TYPE,
        "created_at": now,
        "expires_at": now + lifetime_hours * 3600,
        "request_nonce": uuid.uuid4().hex,
        "target_device_sha256": target_hash(udid),
        "ssh_public_key": ssh_public_key,
        "ssh_key_fingerprint": public_key_fingerprint(ssh_public_key),
        "mac_identity_public_key": base64.b64encode(mac_public).decode(),
        "mac_identity_fingerprint": mac_fingerprint,
    }
    signature = mac_key.sign(canonical(body))
    document = {**body, "signature": base64.b64encode(signature).decode()}
    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise RuntimeError("refusing to overwrite an existing pairing request")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush(); os.fsync(handle.fileno())
    except Exception:
        try: destination.unlink()
        except OSError: pass
        raise
    return {
        "status": "ready", "request": str(destination),
        "ssh_key_fingerprint": body["ssh_key_fingerprint"],
        "mac_identity_fingerprint": mac_fingerprint,
        "expires_at": body["expires_at"],
    }


def read_and_verify_request(path: Path, udid: str, *, now: int | None = None) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    path = path.expanduser().resolve()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_REQUEST_BYTES:
        raise RuntimeError("the pairing request is missing, unsafe, or oversized")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise RuntimeError("the pairing request is malformed")
    signature_text = document.pop("signature", None)
    if (document.get("schema") != REQUEST_SCHEMA
            or document.get("type") != REQUEST_TYPE
            or document.get("target_device_sha256") != target_hash(udid)):
        raise RuntimeError("the pairing request does not match the selected device")
    current = int(time.time()) if now is None else now
    created = document.get("created_at")
    expires = document.get("expires_at")
    if (not isinstance(created, int) or not isinstance(expires, int)
            or created > current + 300 or expires < current or expires - created > 720 * 3600):
        raise RuntimeError("the pairing request is expired or has invalid timestamps")
    ssh_key = document.get("ssh_public_key")
    if (not isinstance(ssh_key, str)
            or public_key_fingerprint(ssh_key) != document.get("ssh_key_fingerprint")):
        raise RuntimeError("the pairing request SSH fingerprint does not match")
    try:
        mac_public = base64.b64decode(document["mac_identity_public_key"], validate=True)
        signature = base64.b64decode(signature_text, validate=True)
        key = Ed25519PublicKey.from_public_bytes(mac_public)
        key.verify(signature, canonical(document))
    except Exception as error:
        raise RuntimeError("the pairing request signature is invalid") from error
    observed_mac = "SHA256:" + base64.b64encode(
        hashlib.sha256(mac_public).digest()).decode().rstrip("=")
    if observed_mac != document.get("mac_identity_fingerprint"):
        raise RuntimeError("the pairing request Mac identity does not match")
    return document


def ssh_base(host: str, port: int, identity: Path, known_hosts: Path,
             host_alias: str) -> list[str]:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise RuntimeError("additional-Mac authorization requires the exact USB loopback tunnel")
    if not 1 <= port <= 65535:
        raise RuntimeError("invalid SSH port")
    for value in (str(identity), str(known_hosts), host_alias):
        if "\n" in value or '"' in value:
            raise RuntimeError("SSH path or host alias contains unsupported characters")
    return [
        "/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f'UserKnownHostsFile="{known_hosts}"',
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"HostKeyAlias={host_alias}",
        "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no", "-i", str(identity),
        "-p", str(port), f"root@{host}",
    ]


def approve_request(*, request: Path, udid: str, identity: Path, host: str,
                    port: int, known_hosts: Path, host_alias: str) -> dict:
    value = read_and_verify_request(request, udid)
    program = r'''import base64,hashlib,json,os,sys,time
value=json.load(sys.stdin);key=value["ssh_public_key"].strip()
fields=key.split();allowed=("ssh-ed25519","ssh-rsa","ecdsa-sha2-nistp256","ecdsa-sha2-nistp384","ecdsa-sha2-nistp521")
if len(fields)<2 or fields[0] not in allowed: raise SystemExit("unsupported public key")
blob=base64.b64decode(fields[1],validate=True)
if len(blob)<32: raise SystemExit("public key is too short")
observed="SHA256:"+base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
if observed!=value["ssh_key_fingerprint"]: raise SystemExit("public key fingerprint mismatch")
directory="/var/root/.ssh";path=directory+"/authorized_keys"
if os.path.islink(directory) or os.path.islink(path): raise SystemExit("unsafe authorized-keys path")
os.makedirs(directory,mode=0o700,exist_ok=True);os.chmod(directory,0o700)
lines=[]
if os.path.exists(path):
 if not os.path.isfile(path): raise SystemExit("authorized-keys path is not a regular file")
 lines=[line.strip() for line in open(path,encoding="utf-8") if line.strip()]
def identity(line):
 parts=line.split();return tuple(parts[:2]) if len(parts)>=2 else (line,"")
keys={identity(line) for line in lines};candidate=identity(key)
if candidate not in keys: lines.append(key)
if len({identity(line) for line in lines})>16: raise SystemExit("authorized Mac limit reached (16)")
temporary=path+".%d.%d.tmp"%(os.getpid(),time.time_ns())
flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL
if hasattr(os,"O_NOFOLLOW"): flags|=os.O_NOFOLLOW
fd=os.open(temporary,flags,0o600)
try:
 with os.fdopen(fd,"w",encoding="utf-8") as handle:
  handle.write("\n".join(lines)+"\n");handle.flush();os.fsync(handle.fileno())
 os.chown(temporary,0,0);os.replace(temporary,path);os.chmod(path,0o600)
except Exception:
 try: os.unlink(temporary)
 except OSError: pass
 raise
print(json.dumps({"status":"authorized","ssh_key_fingerprint":observed,"authorized_key_count":len({identity(line) for line in lines})}))'''
    command = ssh_base(host, port, identity.expanduser().resolve(),
                       known_hosts.expanduser().resolve(), host_alias)
    # Never copy an untrusted comment or control sequence from the request.
    key_fields = value["ssh_public_key"].split()
    approved_key = f"{key_fields[0]} {key_fields[1]} 0-Sky-authorized-Mac"
    completed = subprocess.run(
        command + ["/var/jb/usr/bin/python3 -c " + shlex.quote(program)],
        input=(json.dumps({
            "ssh_public_key": approved_key,
            "ssh_key_fingerprint": value["ssh_key_fingerprint"],
        }, separators=(",", ":")) + "\n").encode(),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=45, check=False,
    )
    if completed.returncode:
        detail = (completed.stdout + completed.stderr).decode("utf-8", "replace")[-1200:]
        raise RuntimeError("device authorization failed: " + detail.strip())
    result = json.loads(completed.stdout)
    result["mac_identity_fingerprint"] = value["mac_identity_fingerprint"]
    result["next_step"] = "On the additional Mac, connect this device by USB and choose Pair This Mac."
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--export-request", type=Path)
    mode.add_argument("--approve-request", type=Path)
    parser.add_argument("--udid", required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--support", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--known-hosts", type=Path)
    parser.add_argument("--host-alias")
    parser.add_argument("--lifetime-hours", type=int, default=168)
    args = parser.parse_args()
    if args.export_request:
        result = export_request(
            udid=args.udid, identity=args.identity, support=args.support,
            destination=args.export_request, lifetime_hours=args.lifetime_hours)
    else:
        if args.known_hosts is None or not args.host_alias:
            raise RuntimeError("approval requires the pinned known-hosts file and host alias")
        result = approve_request(
            request=args.approve_request, udid=args.udid, identity=args.identity,
            host=args.host, port=args.port, known_hosts=args.known_hosts,
            host_alias=args.host_alias)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError,
            json.JSONDecodeError) as error:
        print(f"[0-Sky multi-Mac pairing] FAILED: {error}", file=sys.stderr)
        raise SystemExit(2)
