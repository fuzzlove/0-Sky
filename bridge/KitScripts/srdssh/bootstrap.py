#!/usr/bin/env python3
"""Bring up Dropbear and Procursus on an authorized Apple SRD.

This is a reproducible orchestration layer around Apple's SRD RemoteXPC and
Cryptex interfaces.  It is deliberately not a stock-device exploit.  The
target must be an Apple Security Research Device, Developer Mode must be on,
and the Mac must be approved under Settings > Developer > Paired Macs.

Credits: 0-Sky Project.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import copy
import datetime as dt
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tarfile
import time
from typing import BinaryIO


TOTAL = 9
SRDSH_CRYPTEX_VERSION = "1.2.3"
EXPECTED = {
    "srdsh-minimal-apfs-sealed-udzo.dmg": "54d695055cef778e482c53ec49c522f4d29e4656699985db1bb4af2a130e8f18",
    "srdsh-minimal.gtcd": "c542e01a1987fa386ce7384dd3177aa849b893c14b0728e126319f6bce0d5e66",
    "srdsh-minimal-apfs-sealed.hash": "8375e15e6227f8849c1dd99d174b0a27d81c4dc53891ad1c607a430982dd1cc2",
    "procursus.trustcache": "d14f49d8d8ccce2dba60e8c4f89d692d6e498ee99306da8fe1feb39f96def436",
    "srdsh-authorized-key.pub": "b1cc6b6573d0cc54c82ea5272069da08be34a94ad58b16bef2f2f7c8e07a09ac",
    "bootstrap_1900.tar.zst": "2c639b83423e4365a3a849e2bc7c56671cdcc8da534d424b6b1779a27c0c7c08",
}
UDID_RE = re.compile(r"^[A-Za-z0-9-]{20,80}$")


class ChainError(RuntimeError):
    pass


class HostKeyUnavailable(ChainError):
    """The exact USB endpoint is present but SSH is not accepting keys yet."""


def banner() -> None:
    print("", flush=True)
    print("╔══════════════════════════════════════════════════════════════╗", flush=True)
    print("║  0-Sky • authorized iOS SRD research chain                 ║", flush=True)
    print("║  Credits: 0-Sky Project                     ║", flush=True)
    print("╚══════════════════════════════════════════════════════════════╝", flush=True)


def stage(number: int, title: str, detail: str = "") -> None:
    suffix = f" — {detail}" if detail else ""
    print(f"\n[0-Sky Chain] [{number}/{TOTAL}] {title}{suffix}", flush=True)


def pulse(message: str) -> None:
    print(f"[0-Sky Chain]     ◈ {message}", flush=True)


def run(argv: list[str], *, check: bool = True, capture: bool = False,
        timeout: int | None = None) -> subprocess.CompletedProcess[str]:
    executable = Path(str(argv[0])).name
    phase = Path(str(argv[1])).stem if len(argv) > 1 and str(argv[1]).endswith(".py") else executable
    pulse(f"native phase: {phase}")
    return subprocess.run(
        [str(value) for value in argv], check=check, text=True, timeout=timeout,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_kit_manifest(kit: Path) -> int:
    """Verify the SRDssh subtree against the immutable release manifest.

    Distribution kits have one manifest at their root so every file is bound
    by the same release checksum.  Standalone development kits may retain a
    local manifest.  In either layout, only entries inside the selected
    SRDssh directory are accepted and at least one entry must be present.
    """
    local_sums = kit / "SHA256SUMS"
    root_sums = kit.parent / "SHA256SUMS"
    if local_sums.is_file() and not local_sums.is_symlink():
        sums = local_sums
        prefix = ""
    elif root_sums.is_file() and not root_sums.is_symlink():
        sums = root_sums
        prefix = kit.name.rstrip("/") + "/"
    else:
        raise ChainError(
            "SRDssh checksums are missing. Reinstall 0-Sky Bridge; the "
            "application's embedded kit is incomplete."
        )
    count = 0
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            expected, raw = line.split(None, 1)
        except ValueError as error:
            raise ChainError("malformed SRDssh checksum manifest") from error
        relative = raw.strip().lstrip("*").removeprefix("./")
        if prefix:
            if not relative.startswith(prefix):
                continue
            relative = relative[len(prefix):]
        parts = PurePosixPath(relative).parts
        if not relative or relative.startswith("/") or ".." in parts:
            raise ChainError(f"unsafe SRDssh checksum path: {relative!r}")
        path = kit / relative
        # The sealed SRD payload intentionally contains usr/bin/sh -> toybox.
        # Permit only contained relative links. Absolute, traversing, broken,
        # or escaping links fail closed before a device-changing operation.
        safe = path.is_file()
        if path.is_symlink():
            try:
                target = Path(os.readlink(path))
                resolved_root = kit.resolve(strict=True)
                resolved = path.resolve(strict=True)
                safe = (not target.is_absolute() and ".." not in target.parts
                        and resolved_root in resolved.parents)
            except (OSError, RuntimeError):
                safe = False
        if not safe or sha256(path) != expected:
            raise ChainError(f"SRDssh kit verification failed: {relative}")
        count += 1
    if count < 1:
        raise ChainError("SRDssh checksum manifest is empty")
    pulse(f"verified complete SRDssh manifest: {count} files")
    return count


def verify_inputs(kit: Path, *, procursus: bool) -> None:
    verify_kit_manifest(kit)
    required = [
        "install_cryptex_native.py", "rekey_image.py", "BuildManifest.plist",
        "srdsh-minimal-apfs-sealed-udzo.dmg", "srdsh-minimal.gtcd",
        "srdsh-minimal-apfs-sealed.hash", "procursus.trustcache",
        "srdsh-authorized-key.pub",
    ]
    if procursus:
        required.append("bootstrap_1900.tar.zst")
    for name in required:
        path = kit / name
        if not path.is_file():
            raise ChainError(f"SRDssh kit is incomplete: {name} is missing")
    for name, expected in EXPECTED.items():
        if name not in required:
            continue
        actual = sha256(kit / name)
        if actual != expected:
            raise ChainError(f"bundled {name} digest mismatch: {actual}")
        pulse(f"verified {name}: {actual[:16]}…")
    try:
        plistlib.loads((kit / "BuildManifest.plist").read_bytes())
    except Exception as error:
        raise ChainError(f"invalid BuildManifest.plist: {error}") from error


async def usb_devices() -> list[object]:
    try:
        from pymobiledevice3.usbmux import list_devices
    except ImportError as error:
        raise ChainError(
            "pymobiledevice3 11.3.1 is required; run the 0-Sky setup command"
        ) from error
    devices = list_devices()
    if inspect.isawaitable(devices):
        devices = await devices
    return [item for item in devices
            if str(item.connection_type).upper() == "USB"]


def resolve_udid(requested: str) -> str:
    devices = asyncio.run(usb_devices())
    serials = [str(item.serial) for item in devices]
    if requested != "auto":
        if not UDID_RE.fullmatch(requested):
            raise ChainError("the selected device UDID has an invalid format")
        if requested not in serials:
            raise ChainError(
                f"selected device {requested} is not USB connected; visible: "
                + (", ".join(serials) or "none")
            )
        return requested
    if len(serials) != 1:
        raise ChainError(
            "automatic discovery requires exactly one USB-connected iPhone "
            f"(found {len(serials)}: {', '.join(serials) or 'none'}); "
            "disconnect extra devices or pass --udid"
        )
    return serials[0]


async def _device_info(udid: str) -> dict[str, str]:
    try:
        from pymobiledevice3.lockdown import create_using_usbmux
    except ImportError as error:
        raise ChainError("pymobiledevice3 is unavailable") from error
    client = None
    try:
        client = create_using_usbmux(serial=udid, autopair=False)
        if inspect.isawaitable(client):
            client = await client
        return {
            "udid": udid,
            "product_type": str(client.product_type),
            "product_version": str(client.product_version),
        }
    finally:
        if client is not None:
            result = client.close()
            if inspect.isawaitable(result):
                await result


def device_info(udid: str) -> dict[str, str]:
    return asyncio.run(_device_info(udid))


def ensure_identity(identity: Path, *, mutate: bool) -> Path:
    identity = identity.expanduser().resolve()
    if identity.is_file():
        if identity.stat().st_mode & 0o077:
            raise ChainError(f"SSH key permissions are too broad; run: chmod 600 {identity}")
        pulse(f"caller-owned SSH identity: {identity}")
        return identity
    if not mutate:
        pulse(f"would generate a new Ed25519 identity at {identity}")
        return identity
    identity.parent.mkdir(parents=True, exist_ok=True)
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
         "0-Sky authorized SRD", "-f", str(identity)])
    identity.chmod(0o600)
    pulse("generated a fresh caller-owned key; no private key enters the IPA")
    return identity


def derive_public_key(identity: Path, destination: Path) -> Path:
    result = run(["ssh-keygen", "-y", "-f", str(identity)], capture=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(result.stdout.strip() + " 0-Sky\n", encoding="utf-8")
    destination.chmod(0o644)
    return destination


def fingerprint(path: Path) -> str:
    result = run(["ssh-keygen", "-lf", str(path)], capture=True)
    parts = result.stdout.split()
    if len(parts) < 2:
        raise ChainError(f"could not fingerprint SSH key: {path}")
    return parts[1]


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.4):
            return True
    except OSError:
        return False


def device_host_alias(udid: str) -> str:
    """Return a stable privacy-preserving OpenSSH lookup name."""
    return "0sky-device-" + hashlib.sha256(udid.encode("utf-8")).hexdigest()[:24]


def _parse_host_keys(data: str, alias: str) -> list[tuple[str, str]]:
    allowed = {
        "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    }
    records: list[tuple[str, str]] = []
    for raw in data.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3 or fields[1] not in allowed:
            raise ChainError("device SSH host-key data contains an unsupported record")
        try:
            decoded = base64.b64decode(fields[2], validate=True)
        except Exception as error:
            raise ChainError("device SSH host-key data is malformed") from error
        if len(decoded) < 32:
            raise ChainError("device SSH host key is unexpectedly short")
        records.append((fields[1], fields[2]))
    if not records:
        raise HostKeyUnavailable("device SSH service did not provide a usable host key")
    return sorted(set(records))


def exact_forward_present(udid: str, port: int) -> bool:
    """Reject an occupied port unless its process is visibly exact-UDID bound."""
    processes = subprocess.run(
        ["/bin/ps", "-axo", "command="], check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
    ).stdout
    for line in processes.splitlines():
        if udid not in line:
            continue
        if "iproxy" in line and f"{port}:22" in line and "-u" in line:
            return True
        if ("pymobiledevice3" in line and "usbmux" in line and "forward" in line
                and "--serial" in line and str(port) in line):
            return True
    return False


def ensure_device_host_key_pin(port: int, state: Path, udid: str, *,
                               allow_replace: bool = False,
                               retry_for: float = 0) -> Path:
    """Pin Dropbear through the selected device's exact USB-only forward."""
    if not exact_forward_present(udid, port):
        raise ChainError("refusing SSH host-key enrollment without an exact-UDID USB tunnel")
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    if state.is_symlink():
        raise ChainError("SRDssh state directory must not be a symbolic link")
    os.chmod(state, 0o700)
    known_hosts = state / "device-known-hosts"
    if known_hosts.exists():
        if known_hosts.is_symlink() or not known_hosts.is_file():
            raise ChainError("device SSH known-hosts path is not a regular file")
        if known_hosts.stat().st_mode & 0o077:
            raise ChainError("device SSH known-hosts file must have mode 0600")
        existing_lines = [line for line in known_hosts.read_text(encoding="utf-8").splitlines()
                          if line.strip() and not line.lstrip().startswith("#")]
        alias = device_host_alias(udid)
        if any(line.split()[0] != alias for line in existing_lines if line.split()):
            raise ChainError("device SSH known-hosts alias does not match the selected device")
        existing = _parse_host_keys("\n".join(existing_lines), alias)
    else:
        existing = None

    deadline = time.monotonic() + max(0, retry_for)
    while True:
        completed = subprocess.run(
            ["/usr/bin/ssh-keyscan", "-T", "10", "-p", str(port), "127.0.0.1"],
            check=False, text=True, timeout=15,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )
        try:
            offered = _parse_host_keys(completed.stdout, device_host_alias(udid))
            break
        except HostKeyUnavailable:
            if time.monotonic() >= deadline:
                raise
            pulse("waiting for the installed Dropbear service to publish its host key")
            time.sleep(3)
    if existing is not None and set(existing).intersection(offered):
        return known_hosts
    if existing is not None and not allow_replace:
        raise ChainError(
            "DEVICE_HOST_KEY_MISMATCH: use the verified USB repair workflow; "
            "the existing trust pin was preserved"
        )

    alias = device_host_alias(udid)
    encoded = "".join(f"{alias} {kind} {blob}\n" for kind, blob in offered).encode()
    temporary = state / f".device-known-hosts.{os.getpid()}.{time.time_ns()}.tmp"
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
    pulse("pinned the exact device SSH host key through verified USB")
    return known_hosts


def ssh_base(identity: Path, port: int, state: Path, udid: str) -> list[str]:
    known_hosts = state / "device-known-hosts"
    if ('"' in str(known_hosts) or "\n" in str(known_hosts) or
            not known_hosts.is_file() or known_hosts.is_symlink() or
            known_hosts.stat().st_mode & 0o077):
        raise ChainError("a private regular device SSH host-key pin is required")
    return [
        "/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1", "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=yes", "-o", "LogLevel=ERROR", "-o",
        f'UserKnownHostsFile="{known_hosts}"', "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"HostKeyAlias={device_host_alias(udid)}",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-i", str(identity),
        "-p", str(port), "root@127.0.0.1",
    ]


def ssh_call(base: list[str], command: str, *, check: bool = True,
             capture: bool = False, input_data: bytes | None = None,
             timeout: int = 60) -> subprocess.CompletedProcess:
    pulse("device(root): " + command.splitlines()[0][:140])
    return subprocess.run(
        base + [command], input=input_data, check=check, timeout=timeout,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=input_data is None,
    )


def root_ssh_ready(base: list[str]) -> bool:
    result = ssh_call(
        base, 'test "$(id -u)" = 0 && printf "0_SKY_ROOT_READY\\n"',
        check=False, capture=True, timeout=10,
    )
    stdout = result.stdout.decode("utf-8", "replace") if isinstance(result.stdout, bytes) else result.stdout
    return result.returncode == 0 and "0_SKY_ROOT_READY" in (stdout or "")


def start_forward(python: Path, udid: str, port: int, state: Path) -> None:
    if port_open(port):
        if exact_forward_present(udid, port):
            pulse(f"reusing exact-UDID USB tunnel at 127.0.0.1:{port}")
            return
        raise ChainError(
            f"TCP port {port} is occupied but is not visibly bound to the selected "
            "device's USB forward; choose another --port"
        )
    state.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(state, 0o700)
    log_path = state / f"usbmux-forward-{port}.log"
    log = log_path.open("ab", buffering=0)
    command = [str(python), "-m", "pymobiledevice3", "usbmux", "forward",
               str(port), "22", "--serial", udid]
    pulse("starting persistent USB tunnel: " + " ".join(command))
    process = subprocess.Popen(
        command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True, close_fds=True,
    )
    (state / f"usbmux-forward-{port}.pid").write_text(f"{process.pid}\n")
    for _ in range(40):
        if process.poll() is not None:
            raise ChainError(f"USB tunnel exited early; inspect {log_path}")
        if port_open(port):
            pulse(f"USB tunnel online: 127.0.0.1:{port} → {udid}:22")
            return
        time.sleep(0.25)
    raise ChainError(f"USB tunnel did not listen on port {port}; inspect {log_path}")


def wait_for_root(base: list[str], *, timeout: int = 120) -> None:
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        if root_ssh_ready(base):
            pulse(f"authenticated UID 0 proof received on attempt {attempt}")
            return
        if attempt % 5 == 0:
            pulse(f"Dropbear handshake still converging… attempt {attempt}")
        time.sleep(2)
    raise ChainError("authenticated Dropbear did not become ready before the timeout")


def remote_xpc_preflight(python: Path, udid: str) -> None:
    # Exercise the service actually required by installation rather than
    # treating Bonjour/native browse output as proof. PreferredRsdTunnel tries
    # Apple's native remoted path first and falls back to a paired userspace
    # USB tunnel. This is read-only and stops before any Cryptex replacement.
    program = r'''import asyncio,json,sys
from pymobiledevice3.remote.rsd_tunnel import PreferredRsdTunnel
from pymobiledevice3.services.cryptexd import CryptexdService
async def main():
 async with PreferredRsdTunnel(serial=sys.argv[1],autopair=True) as rsd:
  if str(rsd.udid)!=sys.argv[1]: raise RuntimeError("RemoteXPC UDID mismatch")
  service=CryptexdService(rsd)
  ids=await asyncio.wait_for(service.read_personalization_identifiers(),30)
  nonce=await asyncio.wait_for(service.cryptex_nonce(3),30)
  print(json.dumps({"udid":str(rsd.udid),"product_type":str(rsd.product_type),
   "product_version":str(rsd.product_version),
   "transport":"userspace USB" if rsd.is_in_process_tunnel else "macOS native",
   "research_identifier_present":"img4_chip_rsch" in ids,
   "research_identifier_value":ids.get("img4_chip_rsch"),"nonce_length":len(nonce)}))
asyncio.run(main())'''
    result = run([str(python), "-c", program, udid], check=False,
                 capture=True, timeout=90)
    if result.returncode:
        raise ChainError(
            "RemoteXPC/cryptexd preflight was denied on native and userspace paths. "
            "Enable Developer Mode, unlock the exact SRD, and approve this Mac in "
            "Settings > Developer > Paired Macs.\n" +
            (result.stderr or result.stdout).strip()
        )
    payload = json.loads(result.stdout)
    if payload.get("udid") != udid or int(payload.get("nonce_length", 0)) < 1:
        raise ChainError("RemoteXPC did not prove the exact UDID and domain-3 nonce")
    # img4_chip_rsch is advisory on current iOS 27 builds.  The following TSS
    # preflight is the authorization boundary: it binds Apple's live response
    # to this exact UDID, fresh domain-3 nonce, and personalized input set.
    pulse("RemoteXPC/cryptexd preflight: " + json.dumps(payload, sort_keys=True))


def wait_usb(udid: str, timeout: int = 180) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(str(item.serial) == udid for item in asyncio.run(usb_devices())):
            pulse(f"USB rendezvous restored for {udid}")
            return
        time.sleep(2)
    raise ChainError(f"device {udid} did not reconnect; unlock it and retry")


def personalized_inputs(kit: Path, identity: Path, state: Path) -> dict[str, Path]:
    public = derive_public_key(identity, state / "identity/srdsh-authorized-key.pub")
    bundled = kit / "srdsh-authorized-key.pub"
    own_fp, bundled_fp = fingerprint(public), fingerprint(bundled)
    pulse(f"requested key fingerprint: {own_fp}")
    if own_fp == bundled_fp:
        pulse("fingerprint matches the verified prebuilt image")
        return {
            "image": kit / "srdsh-minimal-apfs-sealed-udzo.dmg",
            "trust_cache": kit / "srdsh-minimal.gtcd",
            "volume_hash": kit / "srdsh-minimal-apfs-sealed.hash",
        }
    pulse("new key detected; rebuilding the minimal Cryptex instead of embedding a secret")
    sys.path.insert(0, str(kit))
    try:
        import rekey_image
        result = rekey_image.build(kit, public, state / "personalized-srdssh")
    finally:
        sys.path.pop(0)
    return {key: Path(value) for key, value in result.items()
            if key in {"image", "trust_cache", "volume_hash"}}


def ticket_cache_options(ticket_cache: Path | None,
                         require_cached_ticket: bool) -> list[str]:
    options: list[str] = []
    if ticket_cache is not None:
        options += ["--ticket-cache", str(ticket_cache)]
    if require_cached_ticket:
        options.append("--require-cached-ticket")
    return options


def install_srdssh(python: Path, kit: Path, inputs: dict[str, Path], udid: str,
                   *, ticket_cache: Path | None = None,
                   require_cached_ticket: bool = False) -> None:
    run([
        str(python), str(kit / "install_cryptex_native.py"),
        "com.liquidsky.srdssh", str(inputs["image"]),
        str(inputs["trust_cache"]), str(inputs["volume_hash"]), SRDSH_CRYPTEX_VERSION,
        udid, str(kit / "BuildManifest.plist"),
        *ticket_cache_options(ticket_cache, require_cached_ticket),
    ])


def _safe_member(member: tarfile.TarInfo) -> tarfile.TarInfo | None:
    name = member.name.removeprefix("./")
    prefix = "var/jb/"
    if name == "var/jb":
        name = "."
    elif name.startswith(prefix):
        name = name[len(prefix):]
    else:
        return None
    parts = PurePosixPath(name).parts
    if name.startswith("/") or ".." in parts:
        raise ChainError(f"unsafe Procursus archive member: {member.name}")
    answer = copy.copy(member)
    answer.name = name
    if answer.islnk():
        link = answer.linkname.removeprefix("./")
        if link.startswith(prefix):
            answer.linkname = link[len(prefix):]
    return answer


def stream_procursus(archive: Path, base: list[str]) -> int:
    try:
        import zstandard
    except ImportError as error:
        raise ChainError("zstandard 0.25.0 is required; run the 0-Sky setup command") from error
    remote = (
        'TARGET=/private/preboot/$(cat /private/preboot/active)/procursus; '
        'mkdir -p "$TARGET" || exit $?; '
        'if [ -L /var/jb ]; then rm /var/jb; '
        'elif [ -e /var/jb ]; then echo "refusing non-symlink /var/jb" >&2; exit 73; fi; '
        'ln -s "$TARGET" /var/jb || exit $?; '
        # A fresh SRDssh Cryptex intentionally contains one multicall Toybox
        # binary but no `tar` symlink.  Invoking `exec tar` therefore fails
        # before Procursus can supply its own tar. Resolve the exact mounted
        # SRDssh payload and invoke the applet explicitly for first bootstrap.
        'TOYBOX=; '
        'for CANDIDATE in /private/var/run/com.apple.security.cryptexd/mnt/'
        'com.liquidsky.srdssh.*/usr/bin/toybox; do '
        'if [ -x "$CANDIDATE" ]; then TOYBOX="$CANDIDATE"; break; fi; done; '
        'if [ -z "$TOYBOX" ]; then echo "SRDssh Toybox is unavailable" >&2; exit 74; fi; '
        'exec "$TOYBOX" tar -xpf - -C "$TARGET"'
    )
    pulse("streaming verified bootstrap directly into active Preboot (no host extraction)")
    process = subprocess.Popen(base + [remote], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert process.stdin is not None
    count = 0
    try:
        with archive.open("rb") as source:
            with zstandard.ZstdDecompressor().stream_reader(source) as decoded:
                with tarfile.open(fileobj=decoded, mode="r|") as incoming:
                    with tarfile.open(fileobj=process.stdin, mode="w|") as outgoing:
                        for member in incoming:
                            safe = _safe_member(member)
                            if safe is None:
                                continue
                            payload: BinaryIO | None = incoming.extractfile(member) if member.isfile() else None
                            outgoing.addfile(safe, payload)
                            count += 1
        process.stdin.close()
        process.stdin = None
        stdout, stderr = process.communicate()
    except Exception:
        process.kill()
        process.wait()
        raise
    if process.returncode:
        raise ChainError(
            f"remote bootstrap extraction failed ({process.returncode}): "
            + stderr.decode("utf-8", "replace")[-2000:]
        )
    pulse(f"transferred {count} Procursus archive entries")
    return count


def configure_procursus(base: list[str]) -> None:
    command = r'''set -eu
chmod 755 /var/jb/prep_bootstrap.sh
NO_PASSWORD_PROMPT=1 /var/jb/usr/bin/sh /var/jb/prep_bootstrap.sh
# The legacy shshd prerm invokes Procursus launchctl, whose private launchd
# symbol set is not compatible with iOS 27. The package is removed below and
# its obsolete daemon was never loaded, so make that retirement script a
# deterministic no-op rather than executing the incompatible client.
if [ -f /var/jb/var/lib/dpkg/info/shshd.prerm ]; then
  printf '%s\n' '#!/bin/sh' 'exit 0' > /var/jb/var/lib/dpkg/info/shshd.prerm
  chmod 755 /var/jb/var/lib/dpkg/info/shshd.prerm
fi
for package in shshd libdimentio0 libkrw0; do
  if /var/jb/usr/bin/dpkg-query -W -f='${db:Status-Abbrev}' "$package" 2>/dev/null | grep -q '^ii'; then
    /var/jb/usr/bin/dpkg --remove --force-depends "$package"
  fi
done
/var/jb/usr/bin/dpkg --configure --pending
printf '%s\n' 'source=bootstrap_1900.tar.zst' \
  'sha256=2c639b83423e4365a3a849e2bc7c56671cdcc8da534d424b6b1779a27c0c7c08' \
  > /var/jb/.srd_procursus_bootstrap
'''
    # Dropbear's initial Cryptex shell is intentionally tiny. Once Procursus
    # is extracted and admitted by the bundled base trust cache, run its
    # full shell explicitly so errexit/nounset semantics are enforced.
    ssh_call(base, "/var/jb/usr/bin/sh -c " + shlex.quote(command), timeout=600)


def write_report(state: Path, report: dict) -> None:
    state.mkdir(parents=True, exist_ok=True)
    report["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
    path = state / "last-run.json"
    temporary = path.with_suffix(".new")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)
    pulse(f"machine-readable chain report: {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--udid", default="auto", help="USB device UDID, or auto")
    parser.add_argument("--identity", type=Path,
                        default=Path.home() / ".ssh/srdsh_ed25519")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--state", type=Path,
                        default=Path.home() / "Library/Application Support/0-Sky/srdssh-state")
    parser.add_argument("--check", action="store_true", help="read-only readiness check")
    parser.add_argument("--dry-run", action="store_true", help="print the chain without mutation")
    parser.add_argument("--force", action="store_true", help="reinstall bootstrap even if healthy")
    parser.add_argument("--force-srdssh", action="store_true",
                        help="replace even a working Dropbear Cryptex with the bundled generation")
    parser.add_argument("--no-reboot", action="store_true")
    parser.add_argument("--ssh-only", action="store_true")
    parser.add_argument(
        "--ticket-cache", type=Path,
        help="optional exact SRD nonce/TSS archive used after live SRD validation",
    )
    parser.add_argument(
        "--require-cached-ticket", action="store_true",
        help="fail rather than contact TSS when no exact cached SRD ticket matches",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        raise ChainError("--port must be between 1 and 65535")
    if args.require_cached_ticket and args.ticket_cache is None:
        raise ChainError("--require-cached-ticket requires --ticket-cache")

    kit = args.kit.expanduser().resolve()
    state = args.state.expanduser().resolve()
    ticket_cache = args.ticket_cache.expanduser().resolve() if args.ticket_cache else None
    if ticket_cache is not None and not ticket_cache.is_dir():
        raise ChainError(f"ticket cache is not a directory: {ticket_cache}")
    identity = ensure_identity(args.identity, mutate=not (args.check or args.dry_run))
    report: dict = {
        "schema": 1, "credit": "0-Sky Project",
        "authorized_srd_only": True, "dry_run": args.dry_run,
        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(), "checks": {},
    }
    banner()
    stage(1, "USB rendezvous", "finding one unambiguous research target")
    udid = resolve_udid(args.udid)
    info = device_info(udid)
    report["device"] = info
    pulse(f"locked target: {udid} • {info['product_type']} • iOS {info['product_version']}")
    try:
        major = int(info["product_version"].split(".", 1)[0])
    except ValueError as error:
        raise ChainError(f"cannot parse target iOS version: {info['product_version']}") from error
    if major < 17:
        raise ChainError("this RemoteXPC path requires iOS 17 or newer")

    stage(2, "Identity seal", "hashes, signatures, and caller-owned SSH identity")
    verify_inputs(kit, procursus=not args.ssh_only)
    report["checks"]["local_inputs"] = True
    if args.check:
        stage(3, "RemoteXPC handshake", "read-only pairing visibility check")
        remote_xpc_preflight(Path(sys.executable), udid)
        # Prove that the research nonce can be turned into a valid TSS ticket
        # without uninstalling or installing anything. This is the final
        # read-only authorization transition before Cryptex mutation.
        run([
            str(Path(sys.executable)), str(kit / "install_cryptex_native.py"),
            "com.liquidsky.srdssh", str(kit / "srdsh-minimal-apfs-sealed-udzo.dmg"),
            str(kit / "srdsh-minimal.gtcd"),
            str(kit / "srdsh-minimal-apfs-sealed.hash"), SRDSH_CRYPTEX_VERSION, udid,
            str(kit / "BuildManifest.plist"), "--preflight",
            *ticket_cache_options(ticket_cache, args.require_cached_ticket),
        ])
        report["checks"]["remotexpc"] = True
        report["checks"]["tss_ticket"] = True
        for number, title in ((4, "Dropbear Cryptex flight"), (5, "Persistence reboot"),
                              (6, "USB tunnel"), (7, "Root SSH proof"),
                              (8, "Procursus rootless bootstrap"), (9, "0-Sky handoff ready")):
            stage(number, title, "skipped in read-only check mode")
        report["passed"] = True
        write_report(state, report)
        return 0
    if args.dry_run:
        stage(3, "RemoteXPC handshake", "would require matching USB + paired SRD identity")
        stage(4, "Dropbear Cryptex flight", "would personalize/install com.liquidsky.srdssh")
        stage(5, "Persistence reboot", "would reboot once and wait for the same UDID")
        stage(6, "USB tunnel", f"would forward 127.0.0.1:{args.port} → device:22")
        stage(7, "Root SSH proof", "would require authenticated uid=0")
        stage(8, "Procursus rootless bootstrap",
              "would stream bootstrap into active Preboot" if not args.ssh_only else "omitted by --ssh-only")
        stage(9, "0-Sky handoff ready", "plan complete; zero device mutations")
        report["passed"] = True
        write_report(state, report)
        return 0

    state.mkdir(parents=True, exist_ok=True)
    # Establish only an exact-UDID, loopback USB route before trusting an SSH
    # host key. The Apple Lockdown session above already proved this selected
    # device; no LAN endpoint or password is accepted as an identity anchor.
    start_forward(Path(sys.executable), udid, args.port, state)
    base: list[str] | None = None
    try:
        ensure_device_host_key_pin(args.port, state, udid)
        base = ssh_base(identity, args.port, state, udid)
        existing_ssh = root_ssh_ready(base)
    except HostKeyUnavailable:
        existing_ssh = False
    # A working UID-0 channel proves only that a previously installed payload
    # is reachable.  It is not current proof that the selected device is an
    # authorized SRD.  Re-establish the exact-UDID research guard before this
    # workflow is allowed to enter any privileged device stage, including the
    # Procursus/package path below.  Pair/Verify Trusted Mac is implemented by
    # the separate read-only pairing coordinator and does not call this path.
    stage(3, "RemoteXPC handshake", "current exact-UDID SRD eligibility check")
    remote_xpc_preflight(Path(sys.executable), udid)
    report["checks"]["remotexpc"] = True

    if existing_ssh and not args.force_srdssh:
        stage(4, "Dropbear Cryptex flight", "healthy generation already mounted; preserving it")
        stage(5, "Persistence reboot", "skipped: no Cryptex replacement occurred")
        stage(6, "USB tunnel", f"reusing 127.0.0.1:{args.port}")
    else:
        stage(4, "Dropbear Cryptex flight", "personalize → ticket → install")
        inputs = personalized_inputs(kit, identity, state)
        install_srdssh(
            Path(sys.executable), kit, inputs, udid,
            ticket_cache=ticket_cache,
            require_cached_ticket=args.require_cached_ticket,
        )
        stage(5, "Persistence reboot", "activating and testing the installed Cryptex")
        if args.no_reboot:
            pulse("reboot suppressed by --no-reboot")
        else:
            run([str(sys.executable), "-m", "pymobiledevice3", "diagnostics",
                 "restart", "--udid", udid])
            time.sleep(8)
            wait_usb(udid)
        stage(6, "USB tunnel", "opening a pinned pymobiledevice3 forward")
        start_forward(Path(sys.executable), udid, args.port, state)
        # A Cryptex replacement may legitimately install a new Dropbear host
        # key. Rotate the pin only here, after exact USB Lockdown and the
        # requested installation both succeeded. Routine verification never
        # replaces a mismatched pin.
        ensure_device_host_key_pin(
            args.port, state, udid, allow_replace=True, retry_for=120)
        base = ssh_base(identity, args.port, state, udid)

    stage(7, "Root SSH proof", "trust is measured by result, not animation")
    if base is None:
        raise ChainError("secure device SSH configuration was not established")
    wait_for_root(base)
    uid = ssh_call(base, "id -u; uname -a", capture=True).stdout
    pulse("device proof:\n" + str(uid).strip())
    report["checks"]["ssh_uid_zero"] = True
    if args.ssh_only:
        stage(8, "Procursus rootless bootstrap", "omitted by --ssh-only")
    else:
        stage(8, "Procursus rootless bootstrap", "active Preboot + /var/jb")
        healthy = ssh_call(base, "/var/jb/usr/bin/dpkg --version >/dev/null 2>&1",
                           check=False).returncode == 0
        if healthy and not args.force:
            pulse("existing Procursus dpkg is healthy; preserving it")
        else:
            entries = stream_procursus(kit / "bootstrap_1900.tar.zst", base)
            if entries < 1:
                raise ChainError("Procursus archive contained no /var/jb entries")
            configure_procursus(base)
        versions = ssh_call(
            base, "/var/jb/usr/bin/dpkg --version | head -1; "
                  "/var/jb/usr/bin/apt-get --version | head -1; "
                  "/var/jb/usr/bin/apt-get check", capture=True, timeout=180,
        ).stdout
        pulse("rootless package layer:\n" + str(versions).strip())
        report["checks"]["procursus"] = True

    stage(9, "0-Sky handoff ready", "Dropbear and rootless package layer verified")
    pulse(f"PASS • {info['product_type']} • iOS {info['product_version']} • uid=0")
    pulse("next: the 0-Sky controller can install apps, packages, and refresh ElleKit")
    report["passed"] = True
    write_report(state, report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ChainError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"\n[0-Sky Chain] FAILED CLOSED: {error}", file=sys.stderr, flush=True)
        raise SystemExit(2)
