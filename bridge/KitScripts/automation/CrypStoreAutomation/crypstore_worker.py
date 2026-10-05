#!/usr/bin/env python3
"""Mac-side worker for 0-Sky Control's authorized SRD Cryptex install queue."""

from __future__ import annotations

import argparse
import asyncio
import base64
import fcntl
import gzip
import hashlib
import importlib.util
import json
import os
import pathlib
import plistlib
import re
import signal
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import traceback
import tarfile
import io
import unicodedata
import zipfile

BASE = pathlib.Path(__file__).resolve().parent
NATIVE = BASE / "native-install"
# Each attached SRD needs its own queue state and advisory lock.  Keep the
# immutable worker/native tooling shared, but permit LaunchAgents to select a
# per-device state directory so one worker can run for every configured UDID.
INSTANCE = pathlib.Path(os.environ.get("CRYPSTORE_INSTANCE_DIR", str(BASE))).expanduser()
JOBS = INSTANCE / "jobs"
LOGS = INSTANCE / "logs"
STATE = INSTANCE / "state.json"
LOCK = INSTANCE / "worker.lock"

DEVICE_HOST = os.environ.get("CRYPSTORE_DEVICE_HOST", "")
DEVICE_USER = os.environ.get("CRYPSTORE_DEVICE_USER", "root")
DEVICE_PORT = os.environ.get("CRYPSTORE_DEVICE_PORT")
DEVICE_REMOTE_PORT = os.environ.get("CRYPSTORE_DEVICE_REMOTE_PORT", "22")
DEVICE_UDID = os.environ.get("CRYPSTORE_DEVICE_UDID", "")
HOST_KEY_FINGERPRINT = os.environ.get("CRYPSTORE_HOST_KEY_FINGERPRINT", "")
DEVICE_KEY = pathlib.Path(os.environ.get("CRYPSTORE_DEVICE_KEY", "")).expanduser()
DEVICE_KNOWN_HOSTS = pathlib.Path(os.environ.get(
    "CRYPSTORE_DEVICE_KNOWN_HOSTS", str(INSTANCE / "device-known-hosts"))).expanduser()
_default_host_alias = "0sky-device-" + hashlib.sha256(DEVICE_UDID.encode()).hexdigest()[:24]
DEVICE_HOST_ALIAS = os.environ.get("CRYPSTORE_DEVICE_HOST_ALIAS", _default_host_alias)
BLUETOOTH_PORT = os.environ.get("CRYPSTORE_BLUETOOTH_PORT", "")
BLUETOOTH_STATE = pathlib.Path(os.environ.get(
    "CRYPSTORE_BLUETOOTH_STATE", str(INSTANCE / "bluetooth/state.json"))).expanduser()
REMOTE_SPOOL = "/var/jb/var/spool/crypstore/jobs"
REMOTE_APPREGISTRARD = "/var/jb/usr/local/libexec/appregistrard-srd"
REMOTE_HEARTBEAT = "/var/jb/var/run/crypstore-worker.json"
MOUNT_ROOT = "/private/var/run/com.apple.security.cryptexd/mnt"
BUILDER = NATIVE / "build_and_install.sh"
MANIFEST = NATIVE / "BuildManifest.plist"
RUNTIME_SYNC = BASE.parent / "tools/srd-runtime-manager/sync_runtime_cryptex.py"
CRYPTEX_UNINSTALLER = NATIVE / "uninstall_cryptex_native.py"
PYMOBILE = pathlib.Path(os.environ.get("SRD_PYTHON") or sys.executable)
JOB_RE = re.compile(r"^[0-9a-fA-F-]{16,64}$")
BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
CRYPTEX_RE = re.compile(r"^codes\.rambo\.research\.crypstore\.[0-9a-f]{16}$")
MAX_IPA_BYTES = 2 * 1024 * 1024 * 1024
# Tool-rich applications such as a-Shell legitimately contain tens of
# thousands of small command/resource files.  Keep a hard anti-zip-bomb cap,
# but do not reject these reviewed bundles solely because they exceed the old
# 20,000-entry limit.  Expansion is independently checked against available
# workspace before extraction.
MAX_IPA_ENTRIES = 100_000
# hdiutil's APFS sealing/conversion can transiently allocate substantially
# more than the sparse image's apparent size. 1.75 GiB is the measured safe
# floor for the 0-Sky recovery IPA; the expansion-based term can raise it for
# larger applications.
MIN_WORKSPACE_HEADROOM = 1792 * 1024 * 1024
# A Cryptex update temporarily needs the new APFS image, its personalized
# derivative, and enough free space for cryptexd/database bookkeeping. Keep a
# fixed floor so even small apps cannot fill /private/var late in a transaction.
MIN_DEVICE_INSTALL_HEADROOM = 1024 * 1024 * 1024

# Do not share or wildcard-remove OpenSSH control sockets across SRDs.  An
# earlier recovery path unlinked every /tmp/crypstore-* socket.  The associated
# ControlPersist masters remained alive without a pathname, so each heartbeat
# created another SSH connection until dropbear/iproxy exhausted its sessions.
_control_identity = DEVICE_UDID or f"{DEVICE_HOST}-{DEVICE_PORT or '22'}"
_control_identity = re.sub(r"[^A-Za-z0-9_.-]", "_", _control_identity)[:48]


def control_path(transport: str) -> pathlib.Path:
    suffix = re.sub(r"[^A-Za-z0-9_.-]", "_", transport)[:12]
    return pathlib.Path(f"/tmp/crypstore-{_control_identity}-{suffix}.sock")


CONTROL_PATH = control_path("configured")


def ssh_base_for(host: str, port: str, transport: str) -> list[str]:
    """Build a host-key-pinned command for one verified transport endpoint."""
    if any(value in str(DEVICE_KNOWN_HOSTS) for value in ('"', "\n", "\r", "\t")):
        raise RuntimeError("device SSH known-hosts path contains unsupported characters")
    known_hosts_value = str(DEVICE_KNOWN_HOSTS).replace("\\", "\\\\").replace(" ", "\\ ")
    return [
        "/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
        # Dropbear's NIST P-256 exchange can stall for minutes on the iOS 27
        # SRD runtime while Curve25519 completes reliably.  Pin the mutually
        # supported KEX so health probes cannot exhaust the daemon with stuck
        # unauthenticated children.
        "-o", "KexAlgorithms=curve25519-sha256",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known_hosts_value}",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"HostKeyAlias={DEVICE_HOST_ALIAS}",
        "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        # iOS 27 SRD key exchange and public-key verification can take tens of
        # seconds. Reuse one pinned connection for the serialized worker calls;
        # ssh() discards this socket whenever the authenticated route changes.
        "-o", "ControlMaster=auto", "-o", "ControlPersist=120",
        "-o", f"ControlPath={control_path(transport)}", "-i", str(DEVICE_KEY),
        "-p", str(port), f"{DEVICE_USER}@{host}",
    ]


SSH_BASE = ssh_base_for(DEVICE_HOST, DEVICE_PORT or "22", "configured")

STATUS_LOCK = threading.Lock()
SSH_LOCK = threading.RLock()
STATUS = {"stage": "Ready", "job_id": None, "detail": "Waiting for an IPA"}


class ControlInstallFailed(RuntimeError):
    def __init__(self, message: str, rollback: str):
        super().__init__(message)
        self.rollback = rollback
STOP_HEARTBEAT = threading.Event()
PAIRING_LIVE = INSTANCE / "pairing-live.json"
PAIRING_CHECK_LOCK = threading.Lock()
LAST_PAIRING_CHECK = 0.0
PAIRING_OPERATION_ACTIVE = threading.Event()
_HOST_MODULES = {}
ACTIVE_SSH_TRANSPORT = "none"


def host_module(name: str):
    """Load one bundled host backend in-process and cache it for this worker."""
    value = _HOST_MODULES.get(name)
    if value is not None:
        return value
    path = INSTANCE / "host-mac" / f"{name}.py"
    if not path.is_file():
        raise FileNotFoundError(path)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    _HOST_MODULES[name] = value
    return value


def resolve_device_udid() -> str:
    """A worker always belongs to one explicit, immutable device identity."""
    if not re.fullmatch(r"[A-Za-z0-9-]{20,80}", DEVICE_UDID):
        raise RuntimeError("CRYPSTORE_DEVICE_UDID is required for this worker instance")
    return DEVICE_UDID


def log(message: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {message}"
    print(line, flush=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    with (LOGS / "worker.log").open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def run(argv, *, input_data: bytes | None = None, timeout=900, cwd=None, env=None, check=True):
    completed = subprocess.run(
        [str(value) for value in argv], input=input_data, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout, cwd=cwd, env=env, check=False,
    )
    if check and completed.returncode != 0:
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(map(str, argv))}\n"
            f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
            f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
        )
    return completed


def run_process_group(argv, *, timeout: int, cwd=None, env=None):
    """Run a build tree with a deadline and terminate all descendants."""
    process = subprocess.Popen(
        [str(value) for value in argv], stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, cwd=cwd, env=env, start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        error.stdout = (error.stdout or b"") + (stdout or b"")
        error.stderr = (error.stderr or b"") + (stderr or b"")
        raise
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)


def _wireless_endpoint_verified() -> bool:
    """Use wireless SSH only after the transport manager verified this UDID.

    The file is written by ``refresh_apple_pairing`` only after Apple's
    CoreDevice/Lockdown session, the persistent 0-Sky Mac key, and the exact
    device identity all validate.  The subsequent SSH handshake independently
    requires the device host key pinned through USB enrollment.
    """
    if not DEVICE_UDID or not DEVICE_KNOWN_HOSTS.is_file() or \
            DEVICE_KNOWN_HOSTS.is_symlink():
        return False
    try:
        live = json.loads(PAIRING_LIVE.read_text(encoding="utf-8"))
        device = live.get("device", {})
        transport = live.get("transport", {}).get("type")
        verified_at = int(live.get("pairing", {}).get("lastVerifiedAt", 0))
        return bool(
            live.get("status") == "verified" and
            live.get("host", {}).get("identityVerified") and
            device.get("udid") == DEVICE_UDID and
            transport in ("WIFI_LOCKDOWN", "NATIVE_REMOTEXPC", "USERSPACE_RSD") and
            0 <= int(time.time()) - verified_at <= 120
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False


def _paired_device_bonjour_host() -> str | None:
    """Derive the device's normal mDNS SSH name from signed pairing evidence.

    ``<UDID>.coredevice.local`` can expose Apple's development SSH endpoint,
    whose host key is intentionally different from the Dropbear key pinned by
    0-Sky over USB.  The trusted-device receipt retains Lockdown's exact
    ``DeviceName``.  Its normal Bonjour hostname reaches the persistent
    Dropbear service and is still accepted only when that USB-pinned key
    matches, so this is discovery rather than a trust relaxation.
    """
    if not DEVICE_UDID:
        return None
    receipt = (
        INSTANCE.parent.parent / "trusted-devices"
        / (hashlib.sha256(DEVICE_UDID.encode()).hexdigest()[:24] + ".json")
    )
    try:
        value = json.loads(receipt.read_text(encoding="utf-8"))
        device = value.get("device", {})
        if device.get("udid") != DEVICE_UDID:
            return None
        name = str(device.get("deviceName") or "").strip()
        if not name:
            return None
        ascii_name = unicodedata.normalize("NFKD", name).encode(
            "ascii", "ignore"
        ).decode("ascii")
        label = re.sub(r"[^A-Za-z0-9]+", "-", ascii_name).strip("-")
        return label + ".local" if label else None
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None


def ssh_candidates() -> list[tuple[list[str], pathlib.Path, str]]:
    configured = (SSH_BASE, CONTROL_PATH, "configured")
    # The normal Dropbear Bonjour endpoint is not an Apple wireless-pairing
    # claim; it is merely another route to the same exact host key that was
    # pinned during USB enrollment.  Use it whenever the signed trusted-device
    # receipt yields an exact hostname.  This avoids forcing large app payloads
    # through a slow usbmux tunnel, and still fails closed on any key mismatch.
    # The configured exact-UDID usbmux route is always first. Wireless is a
    # fallback for the same relationship, never a parallel source of trust.
    relationship = transport_relationship()
    # The configured localhost/usbmux endpoint is a USB route.  Do not spend a
    # long file-transfer timeout on a stale listener after the cable has been
    # removed: once the central model has positively observed USB absence, go
    # directly to the already-verified wireless routes.  Retain the configured
    # route for migration/repair when no relationship record exists yet.
    result: list[tuple[list[str], pathlib.Path, str]] = []
    if not relationship or bool(relationship.get("usbAvailable")):
        result.append(configured)
    if _wireless_endpoint_verified():
        # For the rootless app/data plane, prefer the device's exact Bonjour
        # name after the Apple wireless relationship has been verified.  This
        # avoids hauling large IPA payloads through RemoteXPC's service proxy;
        # the pinned device SSH host key still authenticates the same device.
        # Apple service operations continue to prefer NATIVE_REMOTEXPC in the
        # central transport manager.
        bonjour = _paired_device_bonjour_host()
        if bonjour:
            result.append((ssh_base_for(bonjour, DEVICE_REMOTE_PORT, "bonjour"),
                           control_path("bonjour"), "bonjour"))
        result.append((ssh_base_for(f"{DEVICE_UDID}.coredevice.local", DEVICE_REMOTE_PORT, "wireless"),
                       control_path("wireless"), "wireless"))
    # The Bluetooth tunnel is an application data-plane fallback. Its helper
    # authenticates the device with the bridge token provisioned only after
    # enrollment, and OpenSSH still requires the exact USB-pinned host key and
    # caller-owned private key. It is deliberately last after USB and Wi-Fi.
    try:
        bluetooth = json.loads(BLUETOOTH_STATE.read_text(encoding="utf-8"))
        bluetooth_ready = bool(
            BLUETOOTH_PORT and bluetooth.get("status") == "authenticated" and
            bluetooth.get("authenticated") is True and
            int(bluetooth.get("listen_port", 0)) == int(BLUETOOTH_PORT) and
            0 <= int(time.time()) - int(bluetooth.get("updated_at", 0)) <= 120)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        bluetooth_ready = False
    if bluetooth_ready:
        result.append((ssh_base_for("127.0.0.1", BLUETOOTH_PORT, "bluetooth"),
                       control_path("bluetooth"), "bluetooth"))
    # A device with neither a current transport observation nor a verified
    # wireless route still needs the configured endpoint to report a bounded,
    # useful connection failure rather than an internal empty-candidate error.
    if not result:
        result.append(configured)
    return result


def transport_relationship() -> dict:
    """Read the non-secret central trust/transport model for this UDID."""
    if not DEVICE_UDID:
        return {}
    path = (INSTANCE.parent.parent / "trusted-device-capabilities" /
            (hashlib.sha256(DEVICE_UDID.encode()).hexdigest()[:24] + ".json"))
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        answered = value.get("deviceIdentifier") or value.get("deviceID")
        return value if answered == DEVICE_UDID else {}
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {}


def _reset_control_master(base: list[str], path: pathlib.Path) -> None:
    try:
        run(["/usr/bin/ssh", "-S", path, "-O", "exit", base[-1]],
            timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def ssh(command: str, *, input_data: bytes | None = None, timeout=900, check=True):
    # Heartbeats and install jobs share one multiplexed transport. Serialize
    # them so a reconnect cannot race another request, and recover once from a
    # stale ControlMaster socket after a device reboot or tunnel replacement.
    global ACTIVE_SSH_TRANSPORT
    with SSH_LOCK:
        completed = None
        candidates = ssh_candidates()
        for index, (base, path, transport) in enumerate(candidates):
            completed = run(base + [command], input_data=input_data,
                            timeout=timeout, check=False)
            diagnostic = (completed.stdout + completed.stderr).decode("utf-8", "replace")
            recoverable = completed.returncode == 255 and any(
                marker in diagnostic for marker in (
                    "Connection reset", "Control socket connect", "Broken pipe",
                    "Connection refused", "Connection closed", "Operation timed out",
                    "No route to host", "Could not resolve hostname",
                ))
            if recoverable:
                log(f"secure {transport} device channel changed; resetting only this "
                    "SRD transport and retrying")
                _reset_control_master(base, path)
                completed = run(base + [command], input_data=input_data,
                                timeout=timeout, check=False)
            # A remote program's nonzero result is an application result, not
            # a transport failure. Never repeat a potentially mutating command
            # on another path merely because that program returned 1. Only
            # OpenSSH's transport-level 255 may trigger USB failover.
            if completed.returncode != 255:
                ACTIVE_SSH_TRANSPORT = transport
                break
            if index + 1 < len(candidates):
                log("current device channel unavailable; trying the next host-key-pinned transport")
        assert completed is not None
        if check and completed.returncode:
            raise RuntimeError(
                f"secure device operation failed ({completed.returncode})\n"
                f"stdout:\n{completed.stdout.decode('utf-8', 'replace')}\n"
                f"stderr:\n{completed.stderr.decode('utf-8', 'replace')}"
            )
        return completed


def remote_write(path: str, data: bytes) -> None:
    ssh(f"cat > {shlex.quote(path)}", input_data=data, timeout=60)


def set_status(stage: str, job_id: str | None = None, detail: str = "") -> None:
    with STATUS_LOCK:
        STATUS.update({"stage": stage, "job_id": job_id, "detail": detail})


_HOST_TOOLS_CACHE: tuple[float, dict] = (0.0, {})
SSH_UAT_RECEIPT = INSTANCE / "uat" / "ssh.json"
FRIDA_UAT_RECEIPT = INSTANCE / "uat" / "frida.json"


def host_ssh_uat_status() -> dict:
    """Forward only a fresh, device-bound result from the paired Mac UAT."""
    try:
        if SSH_UAT_RECEIPT.parent.is_symlink():
            return {"result": "UNVERIFIED"}
        descriptor = os.open(SSH_UAT_RECEIPT, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8192 or
                    metadata.st_mode & 0o077 or metadata.st_uid != os.getuid()):
                return {"result": "UNVERIFIED"}
            contents = stream.read(8193)
        if len(contents) > 8192:
            return {"result": "UNVERIFIED"}
        value = json.loads(contents)
        checked_at = int(value["timestamp"])
        checks = value["checks"]
        required = {"usb_identity", "pinned_public_key", "root_shell",
                    "server_process", "localhost_listener", "file_round_trip",
                    "cleanup", "reconnect"}
        if (value.get("schema") != 1 or value.get("result") != "PASS" or
                value.get("device_digest") != hashlib.sha256(DEVICE_UDID.encode()).hexdigest() or
                not HOST_KEY_FINGERPRINT or
                value.get("host_key_fingerprint") != HOST_KEY_FINGERPRINT or
                not isinstance(checks, dict) or
                any(checks.get(name) is not True for name in required) or
                not 0 <= time.time() - checked_at <= 3600):
            return {"result": "UNVERIFIED"}
        transport = value.get("transport")
        if transport not in {"configured", "bonjour", "wireless", "bluetooth"}:
            return {"result": "UNVERIFIED"}
        return {"result": "PASS", "checked_at": checked_at,
                "transport": transport, "checks": sorted(required)}
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"result": "UNVERIFIED"}


def host_frida_uat_status() -> dict:
    """Forward only a fresh, pinned, exact-USB process-enumeration result."""
    try:
        if FRIDA_UAT_RECEIPT.parent.is_symlink():
            return {"result": "UNVERIFIED"}
        descriptor = os.open(FRIDA_UAT_RECEIPT, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 8192 or
                    metadata.st_mode & 0o077 or metadata.st_uid != os.getuid()):
                return {"result": "UNVERIFIED"}
            contents = stream.read(8193)
        if len(contents) > 8192:
            return {"result": "UNVERIFIED"}
        value = json.loads(contents)
        checked_at = int(value["timestamp"])
        checks = value["checks"]
        required = {"usb_identity", "artifact_hash", "server_process",
                    "localhost_listener", "host_version", "process_enumeration"}
        if (value.get("schema") != 1 or value.get("result") != "PASS" or
                value.get("device_digest") != hashlib.sha256(DEVICE_UDID.encode()).hexdigest() or
                not HOST_KEY_FINGERPRINT or
                value.get("host_key_fingerprint") != HOST_KEY_FINGERPRINT or
                value.get("scope") != "read_only_process_enumeration" or
                value.get("host_version") != "17.18.0" or
                value.get("device_version") != "17.18.0" or
                value.get("transport") != "exact_usb_iproxy" or
                not isinstance(checks, dict) or
                any(checks.get(name) is not True for name in required) or
                not 0 <= time.time() - checked_at <= 3600):
            return {"result": "UNVERIFIED"}
        return {"result": "PASS", "checked_at": checked_at,
                "host_version": "17.18.0", "device_version": "17.18.0",
                "transport": "exact_usb_iproxy", "checks": sorted(required),
                "scope": "read_only_process_enumeration"}
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return {"result": "UNVERIFIED"}


def host_tool_inventory() -> dict:
    """Bounded, read-only host probes; the heartbeat never includes paths."""
    global _HOST_TOOLS_CACHE
    if time.monotonic() - _HOST_TOOLS_CACHE[0] < 60:
        return _HOST_TOOLS_CACHE[1]
    managed_frida = INSTANCE.parent.parent / "tools/frida-current/bin/frida"
    managed_objection = INSTANCE.parent.parent / "tools/objection-current/bin/objection"
    managed_mitmproxy = INSTANCE.parent.parent / "tools/mitmproxy-current/bin/mitmproxy"
    commands = {
        "frida_cli": (str(managed_frida) if managed_frida.is_file() else "frida", "--version"),
        "objection": (str(managed_objection) if managed_objection.is_file() else "objection", "version"),
        "lldb": ("lldb", "--version"),
        "mitmproxy": (str(managed_mitmproxy) if managed_mitmproxy.is_file() else "mitmproxy", "--version"),
        "wireshark": ("tshark", "--version"),
        "libimobiledevice": ("ideviceinfo", "--version"),
    }
    applications = {
        "burp_suite": ("Burp Suite.app",),
        "wireshark": ("Wireshark.app",),
        "hopper": ("Hopper Disassembler.app", "Hopper.app"),
        "ida": ("IDA Pro.app", "IDA.app"),
    }
    roots = (pathlib.Path("/Applications"), pathlib.Path.home() / "Applications")
    result: dict[str, dict] = {}
    for key, (name, argument) in commands.items():
        executable = name if pathlib.Path(name).is_file() else shutil.which(name)
        if not executable:
            result[key] = {"detected": False, "probe": "SKIP", "version": None}
            continue
        try:
            completed = subprocess.run([str(executable), argument],
                                       stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, timeout=8, check=False)
            combined = (completed.stdout + b"\n" + completed.stderr).decode("utf-8", "replace")
            version = re.search(r"\b\d+(?:\.\d+){1,3}\b", combined)
            result[key] = {"detected": True,
                           "probe": "PASS" if completed.returncode == 0 else "DEGRADED",
                           "version": version.group(0) if version else None}
        except (OSError, subprocess.TimeoutExpired):
            result[key] = {"detected": True, "probe": "DEGRADED", "version": None}
    for key, names in applications.items():
        detected = any((root / name / "Contents/Info.plist").is_file()
                       for root in roots for name in names)
        previous = result.get(key, {"detected": False, "probe": "SKIP", "version": None})
        if detected and not previous["detected"]:
            result[key] = {"detected": True, "probe": "UNTESTED", "version": None}
    result["ghidra"] = {"detected": shutil.which("ghidraRun") is not None,
                         "probe": "UNTESTED", "version": None}
    _HOST_TOOLS_CACHE = (time.monotonic(), result)
    return result


def send_heartbeat() -> None:
    if not PAIRING_OPERATION_ACTIVE.is_set():
        refresh_apple_pairing(allow_pair=False, minimum_interval=60)
    with STATUS_LOCK:
        payload = dict(STATUS)
    live = {}
    try:
        live = json.loads(PAIRING_LIVE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    mac_fingerprint = live.get("host", {}).get("publicKeyFingerprint")
    if not mac_fingerprint:
        pairing_backend = None
        try:
            pairing_backend = host_module("apple_device_pairing")
            _, mac_fingerprint = pairing_backend.MacIdentity(INSTANCE.parent.parent).ensure()
        except Exception:
            mac_fingerprint = None
    relationship = transport_relationship()
    bluetooth_active = ACTIVE_SSH_TRANSPORT == "bluetooth"
    relationship_trusted = relationship.get("trustState") == "TRUSTED"
    payload.update({"timestamp": int(time.time()), "worker": "0-Sky Control Mac Companion",
                    "device_udid": DEVICE_UDID,
                    "host_name": socket.gethostname(),
                    "device_backend": "PymobiledeviceBackend",
                    "control_installer_backend": "paired-srd-worker-v1",
                    "host_tools": host_tool_inventory(),
                    "ssh_uat": host_ssh_uat_status(),
                    "frida_uat": host_frida_uat_status(),
                    "bridge_version": live.get("bridgeVersion", "1.0.0"),
                    "protocol_version": live.get("protocolVersion", 1),
                    "host_key_fingerprint": HOST_KEY_FINGERPRINT,
                    "apple_pairing_verified": live.get("status") == "verified" or
                        (bluetooth_active and relationship_trusted),
                    "lockdown_session_validated": bool(live.get("pairing", {}).get("lockdownSessionValidated")) or
                        (bluetooth_active and relationship_trusted),
                    "host_identity_verified": bool(live.get("host", {}).get("identityVerified")) or
                        bluetooth_active,
                    "mac_identity_fingerprint": mac_fingerprint,
                    "pairing_error": live.get("errorCode"),
                    "pairing_state": (live.get("events") or [{}])[-1].get("state_after"),
                    "device_info": live.get("device", {}),
                    "research_class": live.get("researchClass", "UNKNOWN"),
                    "remote_services": live.get("transport", {}).get("remoteServices"),
                    "last_pairing_verified_at": live.get("pairing", {}).get("lastVerifiedAt"),
                    "transport_type": ("BLUETOOTH_TUNNEL" if bluetooth_active else
                        (live.get("transport", {}).get("type") or
                        ("USB_LOCKDOWN" if live.get("transport", {}).get("usb") else "NONE"))),
                    "bluetooth_connected": bluetooth_active,
                    "bluetooth_pairing_verified": bool(bluetooth_active and relationship_trusted),
                    "wireless_connected": live.get("transport", {}).get("type") in
                        ("WIFI_LOCKDOWN", "NATIVE_REMOTEXPC", "USERSPACE_RSD"),
                    "trust_state": relationship.get("trustState", "UNKNOWN"),
                    "transport_state": relationship.get("transportState", "NONE"),
                    "session_state": relationship.get("sessionState", "DISCONNECTED"),
                    "usb_available": bool(relationship.get("usbAvailable")),
                    "wifi_available": bool(relationship.get("wifiAvailable")),
                    "wifi_lockdown_enabled": bool(relationship.get("wifiLockdownEnabled",
                        relationship.get("wirelessEnabled", False))),
                    # Pairing verification is durable capability evidence;
                    # wifiAvailable is only the current reachability sample.
                    # Keeping them separate prevents a later USB connection
                    # from regressing 0-Sky Link back to WI-FI PENDING.
                    "wifi_pairing_verified": bool(relationship.get(
                        "wifiPairingVerified",
                        relationship.get("wifiAvailable") and relationship.get(
                            "wifiLockdownEnabled", relationship.get("wirelessEnabled", False)))),
                    "remote_pairing_ready": bool(relationship.get("remotePairingReady")),
                    "wireless_rsd_verified": bool(relationship.get("wirelessRSDVerified"))})
    data = (json.dumps(payload, separators=(",", ":")) + "\n").encode()
    temporary = REMOTE_HEARTBEAT + ".tmp"
    remote_write(temporary, data)
    ssh(f"mv {shlex.quote(temporary)} {shlex.quote(REMOTE_HEARTBEAT)}", timeout=60)


def heartbeat_loop() -> None:
    failures = 0
    retry = (1, 2, 5, 10, 30)
    while not STOP_HEARTBEAT.is_set():
        try:
            send_heartbeat()
            failures = 0
            delay = 5
        except Exception as error:
            delay = retry[min(failures, len(retry) - 1)]
            failures += 1
            log(f"heartbeat failed: {error}; retrying in {delay}s")
        STOP_HEARTBEAT.wait(delay)


def verified_network_pairing(pairing_backend=None) -> dict | None:
    """Return pairing evidence only for an authenticated existing network link."""
    if pairing_backend is None:
        pairing_backend = host_module("apple_device_pairing")
    transport_backend = host_module("apple_device_transport")
    _, fingerprint = pairing_backend.MacIdentity(INSTANCE.parent.parent).ensure()
    manager = transport_backend.AppleDeviceTransportManager(INSTANCE.parent.parent)
    network = asyncio.run(manager.connect(
        DEVICE_UDID, host_fingerprint=fingerprint))
    if network.get("status") != "connected" or not network.get("hostIdentityVerified"):
        return None
    device = network.get("device", {})
    transport = network.get("transport")
    relationship = network.get("relationship", {})
    is_usb = transport in ("USB", "USB_LOCKDOWN")
    return {"operation": "pair_verify", "status": "verified",
            "device": device,
            "pairing": {"applePairingEstablished": True,
                "lockdownSessionValidated": True,
                "expectedUDIDMatched": True,
                "transportValidated": True,
                "lastVerifiedAt": int(time.time())},
            "host": {"identityVerified": True,
                "publicKeyFingerprint": network.get("hostFingerprint")},
            "transport": {"usb": is_usb, "type": transport,
                "remoteServices": {"status": "PASS" if
                    transport == "NATIVE_REMOTEXPC" else "NOT_REQUIRED",
                    "provider": transport}},
            "wirelessPairing": {
                "wifiLockdown": "VERIFIED" if (not is_usb or
                    relationship.get("wifiPairingVerified")) else "ENABLED",
                "remotePairing": "VERIFIED" if
                    relationship.get("remotePairingReady", not is_usb) else "NOT_REQUIRED",
                "wirelessRSD": "VERIFIED" if
                    relationship.get("wirelessRSDVerified", transport == "NATIVE_REMOTEXPC")
                    else "PENDING",
                "usbAvailable": bool(relationship.get("usbAvailable", is_usb)),
                "wifiAvailable": bool(relationship.get("wifiAvailable", not is_usb)),
            },
            "researchClass": "UNKNOWN",
            "events": network.get("events", [])}


def refresh_apple_pairing(*, allow_pair: bool, minimum_interval: float = 0) -> dict:
    """Run the shared structured coordinator in this persistent Bridge process."""
    global LAST_PAIRING_CHECK
    with PAIRING_CHECK_LOCK:
        now = time.monotonic()
        if minimum_interval and now - LAST_PAIRING_CHECK < minimum_interval:
            try: return json.loads(PAIRING_LIVE.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError): return {}
        pairing_backend = None
        try:
            pairing_backend = host_module("apple_device_pairing")
            coordinator = pairing_backend.MacPairingCoordinator(
                INSTANCE.parent.parent, timeout=900 if allow_pair else 30)
            value = asyncio.run(coordinator.run(
                DEVICE_UDID,
                allow_pair=allow_pair,
                allow_host_enrollment=allow_pair,
            ))
        except Exception as error:
            value = {"operation": "pair_verify", "status": "failed",
                     "errorCode": "BACKEND_UNAVAILABLE",
                     "developerDiagnostic": f"{type(error).__name__}: {error}"}

        # A trusted device can legitimately be USB-absent. Always try the
        # existing authenticated network relationship before declaring it
        # offline, including when the USB-only coordinator raised an error.
        if not allow_pair or value.get("status") != "verified":
            try:
                network_value = verified_network_pairing(pairing_backend)
                if network_value is not None:
                    value = network_value
            except Exception as network_error:
                if value.get("status") != "verified":
                    value["networkDiagnostic"] = (
                        f"{type(network_error).__name__}: {network_error}")
        LAST_PAIRING_CHECK = time.monotonic()
        atomic_json(PAIRING_LIVE, value)
        return value


def atomic_json(path: pathlib.Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def remote_result(job_id: str, value: dict) -> None:
    data = (json.dumps(value, separators=(",", ":")) + "\n").encode()
    path = f"{REMOTE_SPOOL}/{job_id}/result.json"
    temporary = path + ".tmp"
    remote_write(temporary, data)
    ssh(f"mv {shlex.quote(temporary)} {shlex.quote(path)}", timeout=30)


def pending_result_path(job_id: str) -> pathlib.Path:
    """Return the host-side durable result used when the device is unwritable."""
    if not JOB_RE.fullmatch(job_id):
        raise ValueError("invalid job identifier")
    return JOBS / job_id / "pending-result.json"


def defer_remote_result(job_id: str, value: dict) -> None:
    """Persist one terminal result without ever rerunning its device mutation."""
    path = pending_result_path(job_id)
    atomic_json(path, value)


def flush_deferred_result(job_id: str) -> bool:
    """Try to publish a deferred terminal result; return False while blocked."""
    path = pending_result_path(job_id)
    if not path.is_file():
        return True
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("status"), int):
            raise RuntimeError("invalid deferred worker result")
        remote_result(job_id, value)
    except Exception as error:
        log(f"{job_id}: deferred result is still pending: {error}")
        return False
    path.unlink(missing_ok=True)
    cleanup_job_artifacts(JOBS / job_id)
    return True


def list_jobs() -> list[str]:
    command = (
        f"mkdir -p {shlex.quote(REMOTE_SPOOL)}; "
        f"for d in {shlex.quote(REMOTE_SPOOL)}/*; do "
        "[ -d \"$d\" ] || continue; [ -f \"$d/result.json\" ] && continue; "
        "if [ -f \"$d/request.json\" ] || [ -f \"$d/processing.json\" ]; "
        "then echo \"$d/request.json\"; fi; done 2>/dev/null"
    )
    result = ssh(command, timeout=60, check=False)
    jobs = []
    for line in result.stdout.decode("utf-8", "replace").splitlines():
        job_id = pathlib.PurePosixPath(line).parent.name
        if JOB_RE.fullmatch(job_id):
            jobs.append(job_id)
    return sorted(set(jobs))


def claim_job(job_id: str) -> dict | None:
    root = f"{REMOTE_SPOOL}/{job_id}"
    command = (
        f"if mv {shlex.quote(root + '/request.json')} {shlex.quote(root + '/processing.json')} "
        f"2>/dev/null; then cat {shlex.quote(root + '/processing.json')}; "
        f"elif [ -f {shlex.quote(root + '/processing.json')} ] && "
        f"[ ! -f {shlex.quote(root + '/result.json')} ]; then "
        f"cat {shlex.quote(root + '/processing.json')}; fi"
    )
    result = ssh(command, timeout=60, check=False)
    if not result.stdout.strip():
        return None
    request = json.loads(result.stdout)
    if (request.get("job_id") != job_id or request.get("operation") not in
            ("install", "control-install", "link-install", "runtime-sync",
             "uninstall-cryptex", "pair-verify", "crane-container-cleanup",
             "crane-target-handoff")):
        raise RuntimeError("invalid queued request")
    return request


def fetch_ipa(job_id: str, destination: pathlib.Path) -> None:
    root = f"{REMOTE_SPOOL}/{job_id}"
    result = ssh(f"cat {shlex.quote(root + '/input.ipa')}", timeout=600)
    destination.write_bytes(result.stdout)
    if destination.stat().st_size < 256:
        raise RuntimeError("queued IPA is empty")


def verify_requested_ipa_sha256(ipa: pathlib.Path, expected: str | None) -> str:
    observed = file_sha256(ipa)
    if expected is not None and (not isinstance(expected, str) or
                                 not re.fullmatch(r"[0-9a-f]{64}", expected) or
                                 observed != expected):
        raise RuntimeError("queued IPA SHA-256 differs from the requested artifact")
    return observed


def normalize_zip_compression(path):
    """Rewrite supported ZIP methods that macOS ditto cannot extract."""
    import copy
    import struct
    import tempfile

    def strip_zip64(extra):
        result = bytearray()
        offset = 0
        while offset < len(extra):
            if offset + 4 > len(extra):
                raise RuntimeError("IPA has malformed ZIP metadata")
            tag, size = struct.unpack_from("<HH", extra, offset)
            end = offset + 4 + size
            if end > len(extra):
                raise RuntimeError("IPA has truncated ZIP metadata")
            if tag != 1:
                result.extend(extra[offset:end])
            offset = end
        return bytes(result)

    temporary = None
    try:
        with zipfile.ZipFile(path) as source:
            entries = source.infolist()
            if len(entries) > MAX_IPA_ENTRIES:
                raise RuntimeError("IPA contains too many archive entries")
            expanded = sum(item.file_size for item in entries)
            if expanded > 16 * 1024 * 1024 * 1024:
                raise RuntimeError("IPA expansion exceeds the 16 GiB safety limit")
            methods = {item.compress_type for item in entries}
            if methods <= {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                return False
            if not methods <= {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                               zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA}:
                raise RuntimeError("IPA uses an unsupported ZIP compression method")
            if shutil.disk_usage(path.parent).free < expanded + MIN_WORKSPACE_HEADROOM:
                raise RuntimeError("Insufficient host space to normalize IPA compression")
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".ipa-compression-",
                                             suffix=".zip", delete=False) as handle:
                temporary = pathlib.Path(handle.name)
            total = 0
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED,
                                 allowZip64=True) as destination:
                destination.comment = source.comment
                for item in entries:
                    clone = copy.copy(item)
                    clone.compress_type = (zipfile.ZIP_STORED if item.is_dir()
                                           else zipfile.ZIP_DEFLATED)
                    clone.extra = strip_zip64(item.extra)
                    # Copy bytes unchanged, including symlink targets. Preserve
                    # Unix modes, names, dates, comments and non-ZIP64 metadata.
                    written = 0
                    with source.open(item) as incoming, destination.open(clone, "w") as outgoing:
                        while True:
                            chunk = incoming.read(1024 * 1024)
                            if not chunk:
                                break
                            written += len(chunk)
                            total += len(chunk)
                            if written > item.file_size or total > expanded:
                                raise RuntimeError("IPA expands beyond its declared size")
                            outgoing.write(chunk)
                    if written != item.file_size:
                        raise RuntimeError("IPA member size mismatch")
        temporary.replace(path)
        return True
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def normalize_ipa_archive(path: pathlib.Path) -> bool:
    """Accept a normal IPA ZIP or one extra bounded gzip transport layer."""
    with path.open("rb") as handle:
        magic = handle.read(4)
    unwrapped = False
    if magic[:2] == b"\x1f\x8b":
        temporary = path.with_suffix(".unwrapped.ipa")
        total = 0
        try:
            with gzip.open(path, "rb") as source, temporary.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_IPA_BYTES:
                        raise RuntimeError("gzip-wrapped IPA exceeds the 2 GiB safety limit")
                    output.write(chunk)
            temporary.replace(path)
            unwrapped = True
        finally:
            temporary.unlink(missing_ok=True)

    with path.open("rb") as handle:
        magic = handle.read(4)
    if magic not in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        raise RuntimeError("selected file is not an IPA ZIP archive")
    recompressed = normalize_zip_compression(path)
    try:
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > MAX_IPA_ENTRIES:
                raise RuntimeError("IPA contains too many archive entries")
            if archive.testzip() is not None:
                raise RuntimeError("IPA ZIP data is damaged")
    except zipfile.BadZipFile as error:
        raise RuntimeError(f"selected IPA ZIP is invalid: {error}") from error
    return unwrapped or recompressed


def cleanup_job_artifacts(job_dir: pathlib.Path) -> None:
    """Keep the audit/result files while removing large temporary payloads."""
    for name in ("cryptex", "extract", "input.ipa", "entitlements"):
        path = job_dir / name
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)


def required_workspace_bytes(ipa: pathlib.Path) -> tuple[int, int]:
    """Return a conservative workspace requirement and ZIP expansion size.

    Installation temporarily holds the received IPA, its extracted app, a
    second copy in the Cryptex root, and APFS/sealed/converted images. A
    preflight turns a late, noisy copytree ENOSPC cascade into one actionable
    error before signing or device mutation begins.
    """
    with zipfile.ZipFile(ipa) as archive:
        expanded = sum(info.file_size for info in archive.infolist())
    required = max(
        MIN_WORKSPACE_HEADROOM,
        ipa.stat().st_size * 2 + expanded * 3 + 256 * 1024 * 1024,
    )
    return required, expanded


def cryptex_image_mebibytes(root: pathlib.Path) -> tuple[int, int]:
    """Return apparent payload bytes and a headroom-safe APFS image size."""
    payload_bytes = sum(
        path.stat().st_size for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    image_mebibytes = max(
        384,
        ((payload_bytes * 2 + 128 * 1024 * 1024 + 64 * 1024 * 1024 - 1)
         // (64 * 1024 * 1024)) * 64,
    )
    return payload_bytes, image_mebibytes


def preflight_workspace(ipa: pathlib.Path) -> None:
    required, expanded = required_workspace_bytes(ipa)
    free = shutil.disk_usage(JOBS).free
    log("workspace preflight: "
        f"free={free // (1024*1024)} MiB, "
        f"required={required // (1024*1024)} MiB, "
        f"expanded={expanded // (1024*1024)} MiB")
    if free < required:
        raise RuntimeError(
            "host workspace has insufficient free space: "
            f"{free // (1024*1024)} MiB free, "
            f"{required // (1024*1024)} MiB required; clear reproducible build "
            "staging/output or choose a larger CRYPSTORE workspace and retry"
        )


def device_free_space_bytes() -> int:
    """Measure the filesystem that stores Cryptex images on the selected SRD."""
    script = (
        "import os\n"
        "value=os.statvfs('/private/var')\n"
        "print(value.f_bavail*value.f_frsize)\n"
    )
    encoded = base64.b64encode(script.encode()).decode()
    completed = ssh(
        f"echo {shlex.quote(encoded)} | /var/jb/usr/bin/base64 -d | "
        "/var/jb/usr/bin/python3 -",
        timeout=30,
    )
    output = completed.stdout.decode("utf-8", "strict").strip()
    if not re.fullmatch(r"[0-9]+", output):
        raise RuntimeError("device free-space probe returned an invalid value")
    return int(output)


def required_device_install_bytes(app: pathlib.Path) -> tuple[int, int, int]:
    """Return required free bytes, payload bytes and planned image bytes."""
    payload_bytes, image_mebibytes = cryptex_image_mebibytes(app)
    image_bytes = image_mebibytes * 1024 * 1024
    required = max(
        MIN_DEVICE_INSTALL_HEADROOM,
        image_bytes * 2 + payload_bytes * 2 + 256 * 1024 * 1024,
    )
    return required, payload_bytes, image_bytes


def preflight_device_workspace(app: pathlib.Path) -> None:
    """Fail before unregistering or replacing an app when the SRD is full."""
    required, payload_bytes, image_bytes = required_device_install_bytes(app)
    free = device_free_space_bytes()
    log(
        "device workspace preflight: "
        f"free={free // (1024*1024)} MiB, "
        f"required={required // (1024*1024)} MiB, "
        f"payload={payload_bytes // (1024*1024)} MiB, "
        f"image={image_bytes // (1024*1024)} MiB"
    )
    if free < required:
        raise RuntimeError(
            "device has insufficient free space for a transactional Cryptex "
            f"install: {free // (1024*1024)} MiB free, "
            f"{required // (1024*1024)} MiB required; remove obsolete 0-Sky "
            "Cryptex generations through the supported cleanup operation or "
            "free device storage, then retry"
        )


def macho(path: pathlib.Path) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    try:
        magic = path.read_bytes()[:4]
    except OSError:
        return False
    return magic in {
        b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    }


def file_sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_sha256(root: pathlib.Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: str(item.relative_to(root))):
        relative = str(path.relative_to(root)).encode()
        if path.is_symlink():
            kind, value = b"L", os.readlink(path).encode()
        elif path.is_file():
            kind, value = b"F", bytes.fromhex(file_sha256(path))
        elif path.is_dir():
            kind, value = b"D", b""
        else:
            kind, value = b"O", b""
        digest.update(kind + b"\0" + relative + b"\0" + value + b"\n")
    return digest.hexdigest()


def remove_transient_markers(app: pathlib.Path) -> list[str]:
    """Remove only our historical routing marker before the outer signature."""
    removed = []
    for path in app.rglob(".appregistrard*"):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
        removed.append(str(path.relative_to(app)))
    return removed


def assert_no_transient_markers(app: pathlib.Path) -> None:
    markers = [str(path.relative_to(app)) for path in app.rglob(".appregistrard*")]
    if markers:
        raise RuntimeError(f"transient marker survived signing: {markers}")


def signed_identity_policy(app: pathlib.Path, bundle_id: str, identifier: str) -> dict:
    with (app / "Info.plist").open("rb") as handle:
        info = plistlib.load(handle)
    executable = app / info["CFBundleExecutable"]
    display = run(["/usr/bin/codesign", "-dvvv", executable], timeout=30, check=False)
    text = (display.stdout + display.stderr).decode("utf-8", "replace")
    cdhashes = re.findall(r"(?:^|\n)CDHash=([0-9a-fA-F]+)", text)
    if not cdhashes:
        raise RuntimeError("signed executable has no CDHash")
    profile_present = (app / "embedded.mobileprovision").is_file()
    return {
        "schema": 2,
        "bundle_identifier": bundle_id,
        "cryptex_identifier": identifier,
        "expected_cdhash": cdhashes[-1].lower(),
        "expected_info_plist_hash": file_sha256(app / "Info.plist"),
        "expected_bundle_sha256": tree_sha256(app),
        "profile_present": profile_present,
        "auto_repair_enabled": not profile_present,
        "max_repairs_per_boot": 2,
        "repair_cooldown_seconds": 300,
        "enrolled_at": int(time.time()),
        "enrolled_by": "0-Sky Control Mac worker after strict codesign verification",
    }


def bundle_executable(bundle: pathlib.Path) -> pathlib.Path | None:
    info = bundle / "Info.plist"
    if not info.is_file():
        return None
    try:
        with info.open("rb") as handle:
            name = plistlib.load(handle).get("CFBundleExecutable")
    except Exception:
        return None
    if isinstance(name, str) and name and (bundle / name).is_file():
        return bundle / name
    return None


def capture_entitlements(binary: pathlib.Path, ent_dir: pathlib.Path) -> pathlib.Path | None:
    completed = run(["/usr/bin/codesign", "--display", "--entitlements", ":-", binary],
                    timeout=30, check=False)
    if completed.returncode:
        return None
    data = completed.stdout.strip()
    if not data:
        return None
    try:
        parsed = plistlib.loads(data)
    except Exception:
        return None
    output = ent_dir / (hashlib.sha256(str(binary).encode()).hexdigest() + ".plist")
    output.write_bytes(plistlib.dumps(parsed, fmt=plistlib.FMT_XML, sort_keys=True))
    return output


def codesign(
    target: pathlib.Path,
    entitlements: pathlib.Path | None = None,
    identifier: str | None = None,
) -> None:
    argv = [
        "/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
        "--generate-entitlement-der",
    ]
    if identifier is not None:
        if not BUNDLE_RE.fullmatch(identifier):
            raise RuntimeError("refusing to sign with an invalid bundle identifier")
        argv += ["--identifier", identifier]
    else:
        argv.append("--preserve-metadata=identifier")
    if entitlements:
        argv += ["--entitlements", entitlements]
    argv.append(target)
    run(argv, timeout=120)


def signing_identifier(bundle: pathlib.Path, *, required: bool = False) -> str | None:
    """Return the validated identifier that must bind a code bundle signature."""
    try:
        with (bundle / "Info.plist").open("rb") as handle:
            identifier = plistlib.load(handle).get("CFBundleIdentifier")
    except (FileNotFoundError, OSError, plistlib.InvalidFileException):
        identifier = None
    if isinstance(identifier, str) and BUNDLE_RE.fullmatch(identifier):
        return identifier
    if required:
        raise RuntimeError(f"{bundle.name} has no valid CFBundleIdentifier")
    return None


def requested_launch_validation(request: dict, app: pathlib.Path) -> str | None:
    """Validate a device-supplied, root-protected companion lifecycle contract."""
    contract = request.get("launch_validation")
    if contract is None:
        return None
    required = {
        "path", "bundle_identifier", "role", "launch_validation",
        "original_executable_sha256",
    }
    if not isinstance(contract, dict) or set(contract) != required:
        raise RuntimeError("application lifecycle contract is malformed")
    if (contract.get("role") != "hidden-companion" or
            contract.get("launch_validation") != "controlled-exit-v1"):
        raise RuntimeError("application lifecycle contract is unsupported")
    with (app / "Info.plist").open("rb") as handle:
        info = plistlib.load(handle)
    bundle_id = info.get("CFBundleIdentifier")
    executable = info.get("CFBundleExecutable")
    tags = info.get("SBAppTags")
    if (bundle_id != contract.get("bundle_identifier") or
            not isinstance(executable, str) or
            not isinstance(tags, list) or "hidden" not in tags):
        raise RuntimeError("hidden companion metadata differs from its lifecycle contract")
    expected_hash = contract.get("original_executable_sha256")
    if (not isinstance(expected_hash, str) or
            not re.fullmatch(r"[0-9a-f]{64}", expected_hash) or
            file_sha256(app / executable) != expected_hash):
        raise RuntimeError("hidden companion executable differs from its lifecycle contract")
    return "controlled-exit-v1"


def fairplay_encrypted(binary: pathlib.Path) -> bool:
    """Return true only for a Mach-O carrying an active FairPlay region."""
    display = run(["/usr/bin/otool", "-l", binary], timeout=30, check=False)
    if display.returncode:
        return False
    text = display.stdout.decode("utf-8", "replace")
    return bool(re.search(
        r"cmd LC_ENCRYPTION_INFO(?:_64)?\b[\s\S]{0,256}?\bcryptid\s+1\b",
        text,
    ))


def extension_point_identifier(bundle: pathlib.Path) -> str | None:
    """Read an app extension point without trusting a package-supplied path."""
    try:
        with (bundle / "Info.plist").open("rb") as handle:
            info = plistlib.load(handle)
    except (FileNotFoundError, OSError, plistlib.InvalidFileException):
        return None
    extension = info.get("NSExtension")
    if not isinstance(extension, dict):
        return None
    identifier = extension.get("NSExtensionPointIdentifier")
    return identifier if isinstance(identifier, str) and identifier else None


def sign_app(app: pathlib.Path, work: pathlib.Path) -> tuple[str, str, str, dict[str, int]]:
    info_path = app / "Info.plist"
    with info_path.open("rb") as handle:
        info = plistlib.load(handle)
    bundle_id = info.get("CFBundleIdentifier")
    executable_name = info.get("CFBundleExecutable")
    if not isinstance(bundle_id, str) or not BUNDLE_RE.fullmatch(bundle_id):
        raise RuntimeError("app has an invalid CFBundleIdentifier")
    if not isinstance(executable_name, str) or not executable_name:
        raise RuntimeError("app has no CFBundleExecutable")
    main = app / executable_name
    if not macho(main):
        raise RuntimeError("app main executable is missing or is not Mach-O")

    suffixes = {".framework", ".appex", ".xpc", ".app"}
    binaries = [path for path in app.rglob("*") if macho(path)]
    bundles = [path for path in app.rglob("*")
               if path.is_dir() and path.suffix.lower() in suffixes]
    extension_points = [
        identifier for path in bundles
        if path.suffix.lower() == ".appex"
        if (identifier := extension_point_identifier(path)) is not None
    ]
    components = {
        "extensions": sum(path.suffix.lower() == ".appex" for path in bundles),
        "network_extensions": sum(
            identifier.startswith("com.apple.networkextension.")
            for identifier in extension_points
        ),
        "packet_tunnel_providers": sum(
            identifier in {
                "com.apple.networkextension.packet-tunnel",
                "com.apple.networkextension.packet-tunnel-provider",
            }
            for identifier in extension_points
        ),
        "frameworks": sum(path.suffix.lower() == ".framework" for path in bundles),
        "xpc_services": sum(path.suffix.lower() == ".xpc" for path in bundles),
        "embedded_apps": sum(path.suffix.lower() == ".app" for path in bundles),
        "mach_o_files": len(binaries),
    }

    if fairplay_encrypted(main):
        # Re-signing an encrypted App Store executable replaces its Apple
        # CodeDirectory with an ad-hoc one. FairPlay then decrypts the text
        # page at launch, so the ad-hoc hash measures different bytes and the
        # kernel kills it as CODESIGNING/Invalid Page. Preserve the complete
        # receipt-bearing signature set instead. The personalized Cryptex
        # trust cache covers those exact CDHashes; this neither decrypts nor
        # bypasses FairPlay, and a non-authorized device can still reject it.
        assert_no_transient_markers(app)
        for binary in binaries:
            run(["/usr/bin/codesign", "--verify", "--ignore-resources",
                 "--verbose=2", binary], timeout=120)
        log("preserved Apple signatures for FairPlay-encrypted application")
        return bundle_id, executable_name, app.name, components

    removed = remove_transient_markers(app)
    if removed:
        log("removed transient pre-sign marker(s): " + ", ".join(removed))

    run(["/usr/bin/xattr", "-cr", app], timeout=120)
    ent_dir = work / "entitlements"
    ent_dir.mkdir(parents=True, exist_ok=True)
    entitlement_map = {binary: capture_entitlements(binary, ent_dir) for binary in binaries}

    # Bind executable CodeDirectories to the same identifier LaunchServices
    # publishes for their containing application/extension/XPC bundle. Keeping
    # a vendor's stale executable identifier can pass host verification yet be
    # killed by AMFI at first launch on the SRD.
    binary_identifiers = {main: bundle_id}
    bundle_identifiers: dict[pathlib.Path, str | None] = {}
    for bundle in bundles:
        required_identifier = bundle.suffix.lower() in {".app", ".appex", ".xpc"}
        identifier = signing_identifier(bundle, required=required_identifier)
        bundle_identifiers[bundle] = identifier
        executable = bundle_executable(bundle)
        if executable is not None and identifier is not None:
            binary_identifiers[executable] = identifier

    # Sign every bare Mach-O first, then nested code bundles from the inside out,
    # and finally the outer app so its CodeResources seals the finished tree.
    for binary in sorted(binaries, key=lambda value: len(value.parts), reverse=True):
        codesign(binary, entitlement_map[binary], binary_identifiers.get(binary))

    for bundle in sorted(bundles, key=lambda value: len(value.parts), reverse=True):
        executable = bundle_executable(bundle)
        codesign(
            bundle,
            entitlement_map.get(executable) if executable else None,
            bundle_identifiers[bundle],
        )
    codesign(app, entitlement_map.get(main), bundle_id)
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app], timeout=120)
    assert_no_transient_markers(app)
    return bundle_id, executable_name, app.name, components


NATIVE_FIRST_PARTY = {
    "com.liquidsky.CrypStore": ("CrypStore.app", "CrypStore"),
    "codes.liquidsky.research.zerosky": ("ZeroSky.app", "ZeroSky"),
}


def prepare_native_control(app: pathlib.Path, bundle_id: str) -> None:
    """Seal the registrar marker into one reviewed 0-Sky application."""
    expected = NATIVE_FIRST_PARTY.get(bundle_id)
    if expected is None or app.name != expected[0]:
        raise RuntimeError("native first-party preparation received another application")
    marker = app / ".appregistrard"
    marker.touch(exist_ok=False)
    run(["/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
         "--generate-entitlement-der", "--preserve-metadata=entitlements",
         "--identifier", bundle_id, app], timeout=120)
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app], timeout=120)


def stop_running_control(bundle_id: str = "com.liquidsky.CrypStore") -> None:
    """Let native registration replace one first-party app after its snapshot."""
    expected = NATIVE_FIRST_PARTY.get(bundle_id)
    if expected is None:
        raise RuntimeError("unknown first-party process")
    suffix = "/" + expected[0] + "/" + expected[1]
    script = '''import json,os,signal,subprocess,time
suffix=''' + repr(suffix) + '''
def running():
 rows=subprocess.check_output(['/bin/ps','-axo','pid=,command='],text=True).splitlines()
 matches=[]
 for row in rows:
  parts=row.strip().split(None,1)
  if len(parts)==2 and parts[1].startswith(('/var/containers/Bundle/Application/', '/private/var/containers/Bundle/Application/')) and parts[1].endswith(suffix):
   matches.append(int(parts[0]))
 return matches
pids=running()
if len(pids)>1: raise RuntimeError('ambiguous first-party foreground processes')
for pid in pids: os.kill(pid,signal.SIGTERM)
deadline=time.monotonic()+8
while running() and time.monotonic()<deadline: time.sleep(.2)
if running(): raise RuntimeError('first-party foreground process did not exit')
print(json.dumps({'stopped':len(pids)}))'''
    observed = ssh("/var/jb/usr/bin/python3 -c " + shlex.quote(script), timeout=20)
    result = json.loads(observed.stdout)
    if result.get("stopped") not in (0, 1):
        raise RuntimeError("first-party foreground stop result is invalid")


def install_app_with_devicectl(app: pathlib.Path, job_dir: pathlib.Path) -> None:
    """Install one reviewed app through Apple's exact-device native service.

    Do not enter pymobiledevice3's ctypes-backed CoreDevice client here. On
    Intel macOS 26 its libffi callback allocator can loop before it opens a
    device session, which defeats the caller's bounded operation timeout.
    ``devicectl`` is already a declared Xcode prerequisite for SRD setup,
    accepts an argv-safe app path, applies its own deadline, and writes a
    machine-readable result. The caller then verifies the installed bytes over
    the independently host-key-pinned SRD channel.
    """
    if not DEVICE_UDID:
        raise RuntimeError("native app installation has no explicitly selected device UDID")
    discovered = run(["/usr/bin/xcrun", "--find", "devicectl"],
                     timeout=30, check=False)
    candidate = pathlib.Path(discovered.stdout.decode("utf-8", "replace").strip())
    if (discovered.returncode or not candidate.is_absolute()
            or candidate.name != "devicectl"):
        raise RuntimeError(
            "Apple devicectl is unavailable. Install the complete supported "
            "Xcode release, open Xcode once to install its required components, "
            "then select it with `sudo xcode-select --switch "
            "/Applications/Xcode.app/Contents/Developer` and press Resume."
        )
    result_path = job_dir / "devicectl-install-result.json"
    log_path = job_dir / "devicectl-install.log"
    result_path.unlink(missing_ok=True)
    log_path.unlink(missing_ok=True)
    completed = run([
        candidate, "device", "install", "app",
        "--device", DEVICE_UDID, str(app),
        "--timeout", "240",
        "--json-output", result_path,
        "--log-output", log_path,
    ], timeout=270, check=False)
    try:
        report = json.loads(result_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            "Apple devicectl did not produce its required JSON result. "
            f"Inspect the private install log at {log_path}."
        ) from error
    installed = report.get("result", {}).get("installedApplications")
    if completed.returncode or not isinstance(installed, list) or not installed:
        raise RuntimeError(
            "Apple devicectl did not confirm native app installation "
            f"(exit {completed.returncode}). Inspect the private install log at "
            f"{log_path}, keep the selected SRD unlocked and connected by USB, "
            "then press Resume."
        )


def install_native_control(app: pathlib.Path, bundle_id: str,
                           executable: str, job_dir: pathlib.Path) -> str:
    """Register reviewed 0-Sky code with Apple's native service and launch it."""
    expected = NATIVE_FIRST_PARTY.get(bundle_id)
    if expected is None or (app.name, executable) != expected:
        raise RuntimeError("native first-party installer received another application")
    stop_running_control(bundle_id)
    install_app_with_devicectl(app, job_dir)
    listing = ssh("/var/jb/usr/bin/uicache -i " + shlex.quote(bundle_id), timeout=30).stdout.decode("utf-8", "replace")
    paths = [line.partition(": ")[2].strip() for line in listing.splitlines()
             if line.startswith("Path: ")]
    if (f"Executable Name: {executable}\n" not in listing or len(paths) != 1
            or not paths[0].endswith("/" + app.name)):
        raise RuntimeError("native first-party registration lacks its executable or exact path")
    remote = ssh("/var/jb/usr/bin/sha256sum " + shlex.quote(paths[0] + "/Info.plist") +
                 " " + shlex.quote(paths[0] + "/" + executable), timeout=30).stdout.decode("utf-8", "replace")
    observed = [line.split()[0] for line in remote.splitlines()]
    expected = [file_sha256(app / "Info.plist"), file_sha256(app / executable)]
    if observed != expected:
        raise RuntimeError("native first-party code differs from the signed Cryptex payload")
    verify_foreground_launch(bundle_id, paths[0], executable)
    return paths[0]


def verify_control_entitlements(app: pathlib.Path, required: dict) -> None:
    if not isinstance(required, dict) or not required:
        raise RuntimeError("Control permission contract is missing")
    shown = run(["/usr/bin/codesign", "-d", "--entitlements", ":-", app],
                timeout=30, check=False)
    if shown.returncode:
        raise RuntimeError("signed Control entitlements cannot be read")
    try:
        effective = plistlib.loads(shown.stdout)
    except (ValueError, plistlib.InvalidFileException) as error:
        raise RuntimeError("signed Control entitlement plist is invalid") from error
    for key, value in required.items():
        if effective.get(key) != value:
            raise RuntimeError("required Control entitlement differs: " + key)


def evaluate_control_compatibility(staged: pathlib.Path) -> dict:
    """Apply the project filter to signed code before changing the SRD.

    Dyld shared-cache entries cannot be proven by a filesystem scan. Those
    unknowns are carried into the transactional launch check and rollback.
    """
    if (BASE / "zero_sky_compat").is_dir():
        sys.path.insert(0, str(BASE))
    source_runtime = BASE.parents[2] / "DeviceRuntime"
    if source_runtime.is_dir():
        sys.path.insert(0, str(source_runtime))
    from zero_sky_compat import Environment
    from zero_sky_compat.engine import Engine
    detected = ssh("/var/jb/usr/bin/python3 -c 'import sys; "
                   "sys.path.insert(0, \"/var/jb/usr/local/libexec\"); "
                   "import json; from dataclasses import asdict; "
                   "from zero_sky_compat.environment import detect; print(json.dumps(asdict(detect())))'",
                   timeout=120)
    environment = Environment(**json.loads(detected.stdout))
    report, _, _ = Engine(INSTANCE / "compatibility", environment).evaluate(staged)
    blocking = [item for item in report.issues if item["severity"] == "mandatory"]
    if blocking:
        issue = blocking[0]
        raise RuntimeError("Control compatibility BLOCKED: " + issue["code"] +
                           " " + issue["path"] + " " + issue["detail"])
    unknown = [item for item in report.issues if item["severity"] == "unknown"]
    # This transaction supplies the reviewed registration adapter itself and
    # proves registration, discovery, foreground launch, and rollback below.
    # A dormant `uicache` reference in Control is therefore adaptation
    # evidence, not evidence that the signed payload is incompatible.
    allowed_unknown = {"DEPENDENCY_MISSING", "DEPENDENCY_UNKNOWN",
                       "ENTITLEMENT_UNVERIFIED",
                       "OBSOLETE_REGISTRATION_COMMAND"}
    unsupported = [item for item in unknown if item["code"] not in allowed_unknown]
    if unsupported:
        issue = unsupported[0]
        raise RuntimeError("Control compatibility BLOCKED: " + issue["code"] +
                           " " + issue["path"] + " " + issue["detail"])
    return {"result": "COMPATIBLE_WITH_ADAPTATION" if unknown else "COMPATIBLE",
            "issues": unknown, "registry_key": report.key}


def snapshot_native_control(job_dir: pathlib.Path,
                            bundle_id: str = "com.liquidsky.CrypStore") -> pathlib.Path | None:
    """Retain only signed application code; MCM user data stays on the device."""
    expected = NATIVE_FIRST_PARTY.get(bundle_id)
    if expected is None:
        raise RuntimeError("unknown first-party snapshot identity")
    script = r'''import json,subprocess,sys
prefix=sys.argv[1]+' : '
rows=subprocess.check_output(['/var/jb/usr/bin/uicache','-l'],text=True).splitlines()
paths=[line[len(prefix):].strip() for line in rows if line.startswith(prefix)]
print(json.dumps(paths))'''
    result = ssh("/var/jb/usr/bin/python3 -c " + shlex.quote(script) + " " +
                 shlex.quote(bundle_id), timeout=30)
    paths = json.loads(result.stdout)
    if not paths:
        return None
    if len(paths) != 1 or not paths[0].endswith("/" + expected[0]):
        raise RuntimeError("existing first-party registration is ambiguous")
    existing = pathlib.PurePosixPath(paths[0])
    if not str(existing).startswith("/private/var/containers/Bundle/Application/"):
        raise RuntimeError("existing first-party app is outside its MCM container")
    archive = ssh("/var/jb/usr/bin/tar -C " + shlex.quote(str(existing.parent)) +
                  " -cf - " + shlex.quote(existing.name), timeout=300).stdout
    destination = job_dir / "rollback" / "Payload"
    destination.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(archive)) as source:
        names = source.getnames()
        if not names or any(name != existing.name and not name.startswith(existing.name + "/")
                            for name in names):
            raise RuntimeError("existing first-party snapshot contains an unsafe path")
        source.extractall(destination, filter="data")
    app = destination / existing.name
    info = plistlib.loads((app / "Info.plist").read_bytes())
    if (info.get("CFBundleIdentifier") != bundle_id or
            info.get("CFBundleExecutable") != expected[1]):
        raise RuntimeError("existing first-party snapshot identity differs")
    marker = app / ".appregistrard"
    if not marker.exists() and not marker.is_symlink():
        # The registrar consumes its empty marker while copying into MCM. A
        # signature made before that copy still seals the marker. Recreate it
        # only when the existing resource envelope proves its exact bytes.
        resources = plistlib.loads((app / "_CodeSignature/CodeResources").read_bytes())
        legacy = resources.get("files", {}).get(".appregistrard")
        modern = resources.get("files2", {}).get(".appregistrard", {}).get("hash2")
        if (legacy == hashlib.sha1(b"").digest() and
                modern == hashlib.sha256(b"").digest()):
            marker.touch(exist_ok=False)
        else:
            raise RuntimeError("existing Control registrar marker missing without signed empty-file evidence")
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", app], timeout=120)
    return app


def rollback_native_control(previous: pathlib.Path | None, job_dir: pathlib.Path,
                            bundle_id: str = "com.liquidsky.CrypStore") -> str:
    expected = NATIVE_FIRST_PARTY.get(bundle_id)
    if expected is None:
        raise RuntimeError("unknown first-party rollback identity")
    if previous is not None:
        marker = previous / ".appregistrard"
        if not marker.is_file():
            prepare_native_control(previous, bundle_id)
        restore = job_dir / "rollback-restore"
        identifier, _ = build_install_cryptex(previous, bundle_id, restore)
        if bundle_id == "codes.liquidsky.research.zerosky":
            mount = locate_mount(identifier, previous.name)
            registration_bytes = sum(
                path.stat().st_size for path in previous.rglob("*")
                if path.is_file() and not path.is_symlink()
            )
            register_and_link(
                bundle_id, expected[1], previous.name, mount,
                registration_bytes,
                launch_policy=foreground_launch_policy(previous))
        else:
            install_native_control(previous, bundle_id, expected[1], restore)
        return "VERIFIED"
    run([PYMOBILE, "-m", "pymobiledevice3", "apps", "uninstall", bundle_id,
         "--native", "--udid", DEVICE_UDID], timeout=300, check=False)
    run([PYMOBILE, CRYPTEX_UNINSTALLER, cryptex_identifier(bundle_id), DEVICE_UDID],
        timeout=180, check=False)
    result = ssh("/var/jb/usr/bin/uicache -l", timeout=30, check=False)
    if any(line.startswith(bundle_id + " : ") for line in result.stdout.decode("utf-8", "replace").splitlines()):
        raise RuntimeError("fresh first-party rollback left a registered app")
    return "VERIFIED"


def process_control_install(job_id: str, request: dict) -> None:
    """Use the pinned Mac backend with a preserved-code rollback source."""
    job_dir = JOBS / job_id
    if job_dir.exists():
        shutil.rmtree(job_dir)
    job_dir.mkdir(parents=True)
    expected_hash = request.get("source_sha256")
    if not isinstance(expected_hash, str) or not re.fullmatch("[0-9a-f]{64}", expected_hash):
        raise RuntimeError("Control request lacks its verified payload hash")
    ipa = job_dir / "input.ipa"
    set_status("Receiving verified Control IPA", job_id)
    fetch_ipa(job_id, ipa)
    if file_sha256(ipa) != expected_hash:
        raise RuntimeError("Control payload changed in transit")
    normalize_ipa_archive(ipa)
    preflight_workspace(ipa)
    extract = job_dir / "extract"
    extract.mkdir()
    run(["/usr/bin/ditto", "-x", "-k", ipa, extract], timeout=300)
    app = extract / "Payload/CrypStore.app"
    if not app.is_dir():
        raise RuntimeError("Control IPA lacks its canonical app")
    bundle_id, executable, _, components = sign_app(app, job_dir)
    if bundle_id != "com.liquidsky.CrypStore" or executable != "CrypStore":
        raise RuntimeError("Control IPA identity differs")
    prepare_native_control(app, bundle_id)
    verify_control_entitlements(app, request.get("required_entitlements"))
    set_status("Checking Control compatibility", job_id)
    compatibility = evaluate_control_compatibility(extract)
    set_status("Checking device workspace", job_id)
    preflight_device_workspace(app)
    previous = snapshot_native_control(job_dir)
    mutated = False
    try:
        set_status("Installing Control Cryptex", job_id)
        mutated = True
        identifier, _ = build_install_cryptex(app, bundle_id, job_dir)
        set_status("Registering Control natively", job_id)
        registered = install_native_control(app, bundle_id, executable, job_dir)
        state = {"bundle_id": bundle_id, "cryptex_identifier": identifier,
                 "registered_path": registered, "installed_at": int(time.time()),
                 "embedded_components": components, **signed_identity_policy(app, bundle_id, identifier)}
        update_state(bundle_id, state)
        remote_result(job_id, {"status": 0, "bundle_id": bundle_id,
                               "registered_path": registered, "rollback": "NOT_NEEDED",
                               "evidence": {"installation": True, "registration": True,
                                            "launch": True, "compatibility": compatibility},
                               "stdout": "Control installed and launched",
                               "stderr": ""})
        set_status("Control verified", job_id)
        cleanup_job_artifacts(job_dir)
    except Exception as error:
        rollback = "NOT_NEEDED"
        if mutated:
            try:
                rollback = rollback_native_control(previous, job_dir)
            except Exception as restore_error:
                rollback = "FAILED:" + type(restore_error).__name__
        raise ControlInstallFailed(f"Control install failed ({type(error).__name__})", rollback) from error


def process_link_install(job_id: str, request: dict) -> None:
    """Update Link with an exact-code snapshot and verified rollback path."""
    bundle_id = "codes.liquidsky.research.zerosky"
    job_dir = JOBS / job_id
    if job_dir.exists():
        shutil.rmtree(job_dir)
    job_dir.mkdir(parents=True)
    expected_hash = request.get("source_sha256")
    if not isinstance(expected_hash, str) or not re.fullmatch("[0-9a-f]{64}", expected_hash):
        raise RuntimeError("Link request lacks its verified payload hash")
    ipa = job_dir / "input.ipa"
    set_status("Receiving verified Link IPA", job_id)
    fetch_ipa(job_id, ipa)
    if file_sha256(ipa) != expected_hash:
        raise RuntimeError("Link payload changed in transit")
    normalize_ipa_archive(ipa)
    preflight_workspace(ipa)
    extract = job_dir / "extract"
    extract.mkdir()
    run(["/usr/bin/ditto", "-x", "-k", ipa, extract], timeout=300)
    app = extract / "Payload/ZeroSky.app"
    if not app.is_dir():
        raise RuntimeError("Link IPA lacks its canonical app")
    observed_id, executable, _, components = sign_app(app, job_dir)
    if observed_id != bundle_id or executable != "ZeroSky":
        raise RuntimeError("Link IPA identity differs")
    prepare_native_control(app, bundle_id)
    verify_control_entitlements(app, request.get("required_entitlements"))
    set_status("Checking Link compatibility", job_id)
    compatibility = evaluate_control_compatibility(extract)
    set_status("Checking device workspace", job_id)
    preflight_device_workspace(app)
    previous = snapshot_native_control(job_dir, bundle_id)
    mutated = False
    try:
        set_status("Installing Link Cryptex", job_id)
        mutated = True
        identifier, _ = build_install_cryptex(app, bundle_id, job_dir)
        mount = locate_mount(identifier, app.name)
        registration_bytes = sum(
            path.stat().st_size for path in app.rglob("*")
            if path.is_file() and not path.is_symlink()
        )
        set_status("Registering Link from its verified Cryptex", job_id)
        # A first Link install has no existing MCM application for devicectl to
        # update. On the Intel/iPhone hardware matrix, devicectl waited for its
        # entire 240-second deadline without committing that initial bundle.
        # Use the already mounted, hash-verified Cryptex with the dedicated
        # appregistrard transaction; this is the same bounded MCM path used by
        # all other fresh imports and it independently verifies installed bytes.
        registered = register_and_link(
            bundle_id, executable, app.name, mount, registration_bytes,
            launch_policy=foreground_launch_policy(app))
        state = {"bundle_id": bundle_id, "cryptex_identifier": identifier,
                 "registered_path": registered, "installed_at": int(time.time()),
                 "embedded_components": components,
                 **signed_identity_policy(app, bundle_id, identifier)}
        update_state(bundle_id, state)
        remote_result(job_id, {"status": 0, "bundle_id": bundle_id,
                               "registered_path": registered, "rollback": "NOT_NEEDED",
                               "evidence": {"installation": True, "registration": True,
                                            "launch": True, "compatibility": compatibility},
                               "stdout": "Link installed and launched", "stderr": ""})
        set_status("Link verified", job_id)
        cleanup_job_artifacts(job_dir)
    except Exception as error:
        rollback = "NOT_NEEDED"
        if mutated:
            try:
                rollback = rollback_native_control(previous, job_dir, bundle_id)
            except Exception as restore_error:
                rollback = "FAILED:" + type(restore_error).__name__
        raise ControlInstallFailed(f"Link install failed ({type(error).__name__})", rollback) from error


def cryptex_identifier(bundle_id: str) -> str:
    digest = hashlib.sha256(bundle_id.encode()).hexdigest()[:16]
    return f"codes.rambo.research.crypstore.{digest}"


def committed_cryptex_matches(mount: str, app: pathlib.Path,
                              executable: str) -> bool:
    """Verify a remotely mounted generation against the just-signed payload.

    cryptexd can finish enrolling and mounting a large image but fail to send
    the final RemoteXPC response before pymobiledevice3's timeout. Only accept
    that ambiguous result when both the Info.plist and main executable hashes
    on the active mount exactly match the local signed app.
    """
    remote_app = f"{mount}/Applications/{app.name}"
    paths = [f"{remote_app}/Info.plist", f"{remote_app}/{executable}"]
    result = ssh("/var/jb/usr/bin/sha256sum " +
                 " ".join(shlex.quote(path) for path in paths),
                 timeout=60, check=False)
    if result.returncode:
        return False
    observed = [line.split()[0].lower() for line in
                result.stdout.decode("utf-8", "replace").splitlines()
                if line.split()]
    expected = [file_sha256(app / "Info.plist"), file_sha256(app / executable)]
    return observed == expected


def build_install_cryptex(app: pathlib.Path, bundle_id: str, job_dir: pathlib.Path) -> tuple[str, pathlib.Path]:
    if bundle_id in NATIVE_FIRST_PARTY:
        marker = app / ".appregistrard"
        if marker.is_symlink() or not marker.is_file() or marker.stat().st_size:
            raise RuntimeError("native first-party registrar marker is invalid")
    else:
        assert_no_transient_markers(app)
    with (app / "Info.plist").open("rb") as handle:
        signed_executable = app / plistlib.load(handle)["CFBundleExecutable"]
    apple_signed_payload = fairplay_encrypted(signed_executable)
    if apple_signed_payload:
        # sign_app() already verified every preserved code object. Apple's
        # older App Store resource envelope uses custom omit rules that modern
        # macOS rejects under --strict even though the receipt-bearing
        # CodeDirectories are intact.
        run(["/usr/bin/codesign", "--verify", "--ignore-resources",
             "--verbose=2", signed_executable], timeout=120)
    else:
        run(["/usr/bin/codesign", "--verify", "--deep", "--strict",
             "--verbose=2", app], timeout=120)
    cryptex_dir = job_dir / "cryptex"
    root = cryptex_dir / "root" / "Applications"
    root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(app, root / app.name, symlinks=True)
    shutil.copy2(BUILDER, cryptex_dir / "build_and_install.sh")
    shutil.copy2(NATIVE / "generate_trust_cache.py", cryptex_dir / "generate_trust_cache.py")
    shutil.copy2(NATIVE / "install_cryptex_native.py", cryptex_dir / "install_cryptex_native.py")
    os.chmod(cryptex_dir / "build_and_install.sh", 0o755)
    os.chmod(cryptex_dir / "generate_trust_cache.py", 0o755)
    identifier = cryptex_identifier(bundle_id)
    version = f"1.0.{int(time.time())}"
    # The carrier application can include the complete offline recovery kit.
    # A fixed 128 MiB APFS image truncates that payload even when the host has
    # ample space. Size from apparent file bytes, add APFS/sealing headroom,
    # and round to a stable 64 MiB boundary.
    payload_bytes, image_mebibytes = cryptex_image_mebibytes(cryptex_dir / "root")
    env = os.environ.copy()
    env.update({
        "CRYPTEXCTL_UDID": DEVICE_UDID,
        "SRDSH_IDENTIFIER": identifier,
        "SRDSH_VERSION": version,
        "SRDSH_ROOT": str(cryptex_dir / "root"),
        "SRDSH_BUILD_MANIFEST": str(MANIFEST),
        "SRDSH_IMAGE_SIZE": f"{image_mebibytes}m",
        # Preserved App Store code is already trusted by Apple and must not be
        # promoted to platform-binary trust by the per-app Cryptex cache.  That
        # promotion activates iOS 26+ Mach IPC restrictions and crashes apps
        # embedding pre-12.9 Firebase Crashlytics during startup.
        "SRDSH_TRUST_CACHE_MODE": (
            "apple-signed" if apple_signed_payload else "payload"
        ),
    })
    log(f"Cryptex image sizing: payload={payload_bytes // (1024*1024)} MiB, "
        f"image={image_mebibytes} MiB")
    timed_out = False
    try:
        # The app Cryptex contains a fixed 384 MiB image. The paired userspace
        # USB transfer completed in about three minutes on a warm Intel test
        # host, but a cold SRD reinstall can legitimately exceed five minutes
        # while cryptexd retires the prior generation. Match the installer's
        # own bounded 900-second transfer deadline and leave two minutes for
        # image creation and exact post-install verification.
        completed = run_process_group(
            [cryptex_dir / "build_and_install.sh"], timeout=1020,
            cwd=cryptex_dir, env=env,
        )
        build_output = completed.stdout + completed.stderr
        returncode = completed.returncode
    except subprocess.TimeoutExpired as error:
        timed_out = True
        build_output = (error.stdout or b"") + (error.stderr or b"")
        returncode = 124
    (job_dir / "cryptex-build.log").write_bytes(build_output)
    if returncode:
        output = build_output.decode("utf-8", "replace")
        # The iOS 27 SRD has been observed to commit and mount the new
        # generation, then time out awaiting only the final RemoteXPC reply.
        # Continue to registration only after an exact signed-payload check.
        try:
            mount = locate_mount(identifier, app.name)
        except Exception as error:
            raise RuntimeError(
                f"Cryptex installer failed ({returncode}): {output[-4000:]}"
            ) from error
        with (app / "Info.plist").open("rb") as handle:
            executable = plistlib.load(handle).get("CFBundleExecutable")
        if not isinstance(executable, str) or not committed_cryptex_matches(
                mount, app, executable):
            raise RuntimeError(
                "Cryptex installer returned non-zero and the active generation "
                f"does not match the signed payload: {output[-4000:]}"
            )
        condition = "timed out" if timed_out else "returned non-zero"
        log(f"Cryptex installer {condition} after a committed install; "
            "accepted exact Info.plist/executable hash proof")
    return identifier, cryptex_dir


def locate_mount(identifier: str, app_name: str) -> str:
    pattern = f"{MOUNT_ROOT}/{identifier}.*"
    command = (
        f"for d in {pattern}; do "
        # cryptexd leaves empty directories for retired generations. Only an
        # actively mounted APFS image is a valid executable target.
        f"if [ -d \"$d/Applications/{app_name}\" ] && "
        "mount | grep -Fq \" on $d (\"; then echo \"$d\"; fi; done"
    )
    mounts = []
    # Cryptexd can acknowledge the install before the APFS generation appears
    # in the mount table. Treat that as an activation race, not an install
    # failure.
    for _ in range(30):
        result = ssh(command, timeout=60, check=False)
        mounts = [line.strip() for line in result.stdout.decode().splitlines() if line.strip()]
        if mounts:
            break
        time.sleep(1)
    if not mounts:
        raise RuntimeError("installed Cryptex mount was not found")
    if len(mounts) != 1:
        raise RuntimeError(f"expected one active Cryptex mount, found {len(mounts)}")
    return mounts[0]


def app_registration_command(registrar: str | None, cryptex_app: str,
                             kernel_major: int, *, fallback: bool = False) -> str:
    """Select one registration model while keeping the result MCM-backed.

    Darwin 25 cannot reliably complete the InstallCoordination transaction,
    but appregistrard's legacy API still creates a real MCM bundle container.
    The raw uicache path is retained only for boot sets with no registrar.
    """
    if registrar is None:
        return f"/var/jb/usr/bin/uicache -p {shlex.quote(cryptex_app)}"
    legacy_mcm = kernel_major == 25 or fallback
    suffix = " --no-install-coordination" if legacy_mcm else ""
    return (
        f"{shlex.quote(registrar)} register --path {shlex.quote(cryptex_app)} "
        f"--absolute{suffix}"
    )


def mcm_matches_cryptex(registered_app: str, cryptex_app: str,
                        executable: str) -> bool:
    """Require both identity metadata and executable bytes from this generation."""
    match = ssh(
        f"cmp -s {shlex.quote(registered_app + '/' + executable)} "
        f"{shlex.quote(cryptex_app + '/' + executable)} && "
        f"cmp -s {shlex.quote(registered_app + '/Info.plist')} "
        f"{shlex.quote(cryptex_app + '/Info.plist')}",
        timeout=30, check=False,
    )
    return match.returncode == 0


def launch_services_path(bundle_id: str) -> str | None:
    """Return the exact bundle URL that uiopen will launch for this identity."""
    listing = ssh("/var/jb/usr/bin/uicache -l 2>/dev/null", timeout=30,
                  check=False)
    prefix = bundle_id + " : "
    paths = [line[len(prefix):].strip() for line in
             listing.stdout.decode("utf-8", "replace").splitlines()
             if line.startswith(prefix)]
    if len(paths) > 1:
        raise RuntimeError("multiple LaunchServices records for " + bundle_id)
    return paths[0] if paths else None


def reconcile_launch_services_url(bundle_id: str, registered_app: str,
                                  cryptex_app: str, executable: str,
                                  registrar: str, timeout: int) -> str:
    """Require uiopen's exact URL to carry the reviewed Cryptex generation."""
    published = launch_services_path(bundle_id)
    if published == registered_app:
        return registered_app
    if published and mcm_matches_cryptex(published, cryptex_app, executable):
        log("adopted existing LaunchServices URL with exact Cryptex bytes")
        return published
    if published:
        retired = ssh(
            f"{shlex.quote(registrar)} unregister {shlex.quote(published)}",
            timeout=60, check=False)
        if retired.returncode:
            detail = (retired.stderr or retired.stdout).decode(
                "utf-8", "replace").strip()
            raise RuntimeError("stale LaunchServices URL could not be retired: " + detail)
    published_result = ssh(
        f"{shlex.quote(registrar)} register --path "
        f"{shlex.quote(registered_app)} --absolute",
        timeout=timeout, check=False)
    if published_result.returncode:
        detail = (published_result.stderr or published_result.stdout).decode(
            "utf-8", "replace").strip()
        raise RuntimeError("MCM bundle was copied but icon registration failed: " + detail)
    actual = launch_services_path(bundle_id)
    if actual != registered_app:
        raise RuntimeError("MCM publication retained stale LaunchServices URL: "
                           + str(actual))
    log("published exact MCM bundle URL to LaunchServices")
    return registered_app


def repair_stale_mcm_copy(registered_app: str, cryptex_app: str,
                          executable: str, registrar: str | None,
                          kernel_major: int, finder_command: str,
                          register_timeout: int, fallback_used: bool) -> tuple[str, bool]:
    """Retry one bounded MCM copy when coordination retained older signed code.

    appregistrard replaces only the bundle in its MCM bundle container. The
    separate application data container is preserved. A copy or publication
    return code alone is never accepted as proof of the new app generation.
    """
    if mcm_matches_cryptex(registered_app, cryptex_app, executable):
        return registered_app, fallback_used
    if registrar is None or fallback_used:
        raise RuntimeError("registered MCM bundle differs from authorized Cryptex")
    fallback = app_registration_command(
        registrar, cryptex_app, kernel_major, fallback=True)
    copied = ssh(fallback, timeout=register_timeout, check=False)
    found = ssh(finder_command, timeout=60)
    refreshed = found.stdout.decode("utf-8", "replace").strip().splitlines()
    if not refreshed or not mcm_matches_cryptex(
            refreshed[-1], cryptex_app, executable):
        detail = (copied.stderr or copied.stdout).decode(
            "utf-8", "replace").strip()[-500:]
        raise RuntimeError(
            "bounded MCM repair did not materialize the authorized Cryptex bundle"
            + (": " + detail if copied.returncode and detail else ""))
    log("replaced stale MCM bundle with byte-identical authorized Cryptex copy")
    return refreshed[-1], True


def recent_launch_crash(bundle_id: str, started_at: int) -> str:
    """Return a bounded crash reason for this launch without copying reports."""
    inspector = r'''import glob,json,os,sys
bundle_id,started=sys.argv[1],int(sys.argv[2])
for path in sorted(glob.glob('/var/mobile/Library/Logs/CrashReporter/*.ips'),
                   key=lambda p: os.path.getmtime(p), reverse=True):
 try:
  if os.path.getmtime(path) < started-2: break
  raw=open(path,'r',errors='replace').read()
  first,rest=raw.split('\n',1)
  header=json.loads(first)
  if header.get('bundleID') != bundle_id: continue
  body=json.JSONDecoder().raw_decode(rest.lstrip())[0]
  exc=body.get('exception') or {}
  term=body.get('termination') or {}
  parts=[]
  if exc.get('type'): parts.append(str(exc['type']))
  if exc.get('signal'): parts.append(str(exc['signal']))
  if exc.get('subtype'): parts.append(str(exc['subtype']))
  if exc.get('message'): parts.append(str(exc['message']))
  if term.get('namespace'): parts.append('termination='+str(term['namespace']))
  print('; '.join(parts)[:1200])
  break
 except Exception: pass
'''
    encoded = base64.b64encode(inspector.encode()).decode()
    result = ssh(
        f"echo {shlex.quote(encoded)} | /var/jb/usr/bin/base64 -d | "
        f"/var/jb/usr/bin/python3 - {shlex.quote(bundle_id)} {started_at}",
        timeout=30, check=False,
    )
    return result.stdout.decode("utf-8", "replace").strip()[:1200]


def verify_foreground_launch(bundle_id: str, registered_app: str,
                             executable: str, *, observation_seconds: float = 8.0,
                             launch_validation: str | None = None) -> None:
    """Require an imported foreground app to survive its startup window.

    Registration is not a launch postcondition.  The former three-second
    snapshot missed apps that started and immediately crashed, then reported a
    successful import.  Observe both process appearance and continued life so
    broken imports fail with the device's concise crash reason.
    """
    started_at = int(time.time())
    opened = ssh(
        f"/var/jb/usr/bin/uiopen --bundleid {shlex.quote(bundle_id)}",
        timeout=30, check=False,
    )
    if opened.returncode:
        detail = (opened.stderr or opened.stdout).decode(
            "utf-8", "replace").strip()
        raise RuntimeError("installed app could not be launched: " + detail)

    if launch_validation == "controlled-exit-v1":
        time.sleep(1.0)
        reason = recent_launch_crash(bundle_id, started_at)
        if reason:
            raise RuntimeError("hidden companion launch crashed (" + reason + ")")
        probe = ssh("ps -axo command=", timeout=30, check=False)
        expected = f"{registered_app}/{executable}"
        expected_paths = {expected}
        if expected.startswith("/private/var/"):
            expected_paths.add(expected[len("/private"):])
        if any(line.strip().split(None, 1)[0] in expected_paths
               for line in probe.stdout.decode("utf-8", "replace").splitlines()
               if line.strip()):
            raise RuntimeError("hidden companion did not complete its controlled exit")
        log(f"controlled hidden-companion launch verified for {bundle_id}")
        return
    if launch_validation is not None:
        raise RuntimeError("unknown application launch validation contract")

    expected = f"{registered_app}/{executable}"
    # MCM reports canonical /private/var URLs while proc_pidpath/ps presents
    # the equivalent /var symlink on current iOS.  Compare both spellings;
    # treating that alias difference as "never launched" was itself a false
    # negative in the first strict launch-postcondition implementation.
    expected_paths = {expected}
    if expected.startswith("/private/var/"):
        expected_paths.add(expected[len("/private"):])
    deadline = time.monotonic() + observation_seconds
    appeared = False
    while time.monotonic() < deadline:
        probe = ssh("ps -axo command=", timeout=30, check=False)
        running = any(
            line.strip().split(None, 1)[0] in expected_paths
            for line in probe.stdout.decode("utf-8", "replace").splitlines()
            if line.strip()
        )
        if running:
            appeared = True
        elif appeared:
            reason = recent_launch_crash(bundle_id, started_at)
            suffix = f" ({reason})" if reason else ""
            raise RuntimeError(
                "installed app exited during launch verification" + suffix
            )
        time.sleep(0.5)
    if not appeared:
        reason = recent_launch_crash(bundle_id, started_at)
        suffix = f" ({reason})" if reason else ""
        raise RuntimeError("installed app never reached a running state" + suffix)
    log(f"launch verified for {bundle_id} over {observation_seconds:.1f}s")


def foreground_launch_policy(app: pathlib.Path,
                             launch_validation: str | None = None) -> str:
    """Return the evidence required for this app's declared presentation.

    A package can contain an ``SBAppTags=hidden`` companion solely to expose
    intents or extensions. LaunchServices intentionally does not foreground
    those bundles, so waiting for a process is a false failure. They still
    pass the same signed Cryptex, byte identity, MCM, LaunchServices, and
    PluginKit checks. Visible apps retain the strict launch and survival test.
    """
    try:
        info = plistlib.loads((app / "Info.plist").read_bytes())
    except (OSError, ValueError, TypeError) as error:
        raise RuntimeError("app presentation metadata is invalid") from error
    tags = info.get("SBAppTags", [])
    if not isinstance(tags, list) or not all(isinstance(value, str) for value in tags):
        raise RuntimeError("app presentation tags are invalid")
    if "hidden" in tags:
        if launch_validation != "controlled-exit-v1":
            raise RuntimeError("hidden app lacks a reviewed lifecycle contract")
        return "CONTROLLED_EXIT"
    if launch_validation is not None:
        raise RuntimeError("visible app received a hidden companion lifecycle contract")
    return "REQUIRED"


def mark_trollstore_owned_mcm(bundle_id: str, registered_app: str,
                             cryptex_app: str, executable: str) -> None:
    """Mark only a verified, byte-identical MCM copy; never alter signed code."""
    verifier = r'''import hashlib,os,pathlib,plistlib,stat,sys
bundle_id,registered_app,cryptex_app,executable=sys.argv[1:]
app=pathlib.Path(registered_app);container=app.parent
if app.is_symlink() or container.is_symlink() or container.parent!=pathlib.Path('/private/var/containers/Bundle/Application'):
 raise SystemExit('Unexpected MCM app path')
if not app.is_dir():raise SystemExit('MCM app is missing')
with (app/'Info.plist').open('rb') as f:info=plistlib.load(f)
with (container/'.com.apple.mobile_container_manager.metadata.plist').open('rb') as f:metadata=plistlib.load(f)
if info.get('CFBundleIdentifier')!=bundle_id or metadata.get('MCMMetadataIdentifier')!=bundle_id:
 raise SystemExit('MCM bundle identity mismatch')
def sha(path):
 h=hashlib.sha256()
 with open(path,'rb') as f:
  for block in iter(lambda:f.read(1024*1024),b''):h.update(block)
 return h.digest()
if sha(app/executable)!=sha(pathlib.Path(cryptex_app)/executable):
 raise SystemExit('MCM executable differs from authorized Cryptex')
marker=container/'_TrollStore'
if marker.is_symlink():raise SystemExit('Unsafe ownership marker')
if marker.exists():
 metadata=os.stat(marker,follow_symlinks=False)
 if not stat.S_ISREG(metadata.st_mode) or metadata.st_size!=0:raise SystemExit('Unexpected ownership marker')
else:
 owner=container.stat()
 fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
 try:os.fchown(fd,owner.st_uid,owner.st_gid)
 finally:os.close(fd)
print(str(marker))
'''
    command = (
        '/var/jb/usr/bin/python3 -c ' + shlex.quote(verifier) + ' '
        + ' '.join(shlex.quote(value) for value in
                   (bundle_id, registered_app, cryptex_app, executable))
    )
    result = ssh(command, timeout=60)
    marker = result.stdout.decode('utf-8', 'replace').strip()
    if marker != str(pathlib.Path(registered_app).parent / '_TrollStore'):
        raise RuntimeError('MCM ownership marker verification failed')
    log('verified TrollStore ownership marker in MCM container')


def ensure_trollrecorder_srd_service(bundle_id: str, registered_app: str,
                                    cryptex_app: str) -> None:
    """Install or refresh the verified vendor daemon after MCM registration."""
    if bundle_id != 'wiki.qaq.trapp':
        return
    program = "import glob,hashlib,json,os,pathlib,plistlib,re,subprocess,sys,time\nbundle_id,registered_app,cryptex_app=sys.argv[1:]\nif bundle_id!='wiki.qaq.trapp':raise SystemExit('Unexpected bundle')\nlabel='wiki.qaq.trservices';service='wiki.qaq.trapp.xpc'\napp=pathlib.Path(registered_app);container=app.parent\nif app.is_symlink() or container.is_symlink() or container.parent!=pathlib.Path('/private/var/containers/Bundle/Application'):\n raise SystemExit('Unsafe MCM app path')\nwith (app/'Info.plist').open('rb') as f:info=plistlib.load(f)\nwith (container/'.com.apple.mobile_container_manager.metadata.plist').open('rb') as f:metadata=plistlib.load(f)\nmarker=container/'_TrollStore'\nif info.get('CFBundleIdentifier')!=bundle_id or info.get('CFBundleExecutable')!='TRApp' or metadata.get('MCMMetadataIdentifier')!=bundle_id or marker.is_symlink() or not marker.is_file() or marker.stat().st_size!=0:\n raise SystemExit('TrollRecorder MCM ownership verification failed')\ndef sha(path):\n h=hashlib.sha256()\n with open(path,'rb') as f:\n  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)\n return h.hexdigest()\nbinary=app/'TRCallMonitor';mounted=pathlib.Path(cryptex_app)/'TRCallMonitor'\nif not binary.is_file() or sha(binary)!=sha(mounted):raise SystemExit('Daemon differs from authorized Cryptex')\nexpected_helper='a2d095b681cd4bf1ac819a7052b5b376516ed663bd989edc60d25297fa1e9bbc'\nhelpers=glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.emp0ry.localfence.srd-repair2.*/usr/bin/launchctl-srd')+glob.glob('/private/var/run/com.apple.security.cryptexd/mnt/com.liquidsky.launch-helper.recovery-*/usr/bin/launchctl-srd')\ntrusted=[p for p in helpers if sha(p)==expected_helper]\nif len(trusted)==1:ctl=trusted[0]\nelse:\n ctl='/var/jb/usr/bin/launchctl'\n if sha(ctl)!=expected_helper:raise SystemExit('No trusted SRD launchctl helper')\nversion=subprocess.run([ctl,'version'],capture_output=True,timeout=8)\nif version.returncode:raise SystemExit('SRD launchctl helper cannot start')\nplist=pathlib.Path('/var/jb/Library/LaunchDaemons/'+label+'.plist')\ndata={'Label':label,'ProgramArguments':[str(binary)],'UserName':'root','RunAtLoad':True,'KeepAlive':False,'MachServices':{service:True},'0SkyManaged':True}\ndef job():\n result=subprocess.run([ctl,'print','system/'+label],capture_output=True,timeout=8)\n text=result.stdout.decode(errors='replace')\n path=re.search(r'^\\s*program = (.+)$',text,re.M)\n pid=re.search(r'^\\s*pid = ([0-9]+)$',text,re.M)\n return {'loaded':result.returncode==0,'program':path.group(1).strip() if path else None,'pid':int(pid.group(1)) if pid else None}\ndef save(payload):\n temporary=plist.with_name(plist.name+'.0sky-'+str(os.getpid()))\n fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o644)\n try:\n  with os.fdopen(fd,'wb') as f:f.write(payload);f.flush();os.fsync(f.fileno())\n  os.replace(temporary,plist)\n finally:\n  if temporary.exists():temporary.unlink()\nold=plist.read_bytes() if plist.exists() else None\nold_data=plistlib.loads(old) if old else None\nif old_data and (old_data.get('Label')!=label or not (old_data.get('0SkyManaged') is True or old_data.get('0SkyTest') is True)):\n if old_data.get('ProgramArguments')==[str(binary)] and job()['pid']:\n  print(json.dumps({'vendor_job_healthy':True,'job':job()}));raise SystemExit(0)\n raise SystemExit('Existing vendor daemon job is not managed by 0-Sky')\nbefore=job()\nif before['program']==str(binary) and before['pid']:\n if old_data!=data:save(plistlib.dumps(data))\n print(json.dumps({'action':'promoted' if old_data!=data else 'unchanged','job':job(),'plist':str(plist)}));raise SystemExit(0)\nchanged=False\ntry:\n if before['loaded']:\n  stopped=subprocess.run([ctl,'bootout','system/'+label],capture_output=True,timeout=12)\n  if stopped.returncode:raise RuntimeError('Could not retire prior TrollRecorder job: '+stopped.stderr.decode(errors='replace')[-350:])\n save(plistlib.dumps(data));changed=True\n started=subprocess.run([ctl,'bootstrap','system',str(plist)],capture_output=True,timeout=12)\n if started.returncode:raise RuntimeError('Could not bootstrap TrollRecorder: '+started.stderr.decode(errors='replace')[-350:])\n current={}\n for _ in range(16):\n  time.sleep(.5);current=job()\n  if current['program']==str(binary) and current['pid']:break\n if current.get('program')!=str(binary) or not current.get('pid'):raise RuntimeError('TrollRecorder daemon did not stay running')\n print(json.dumps({'action':'created' if old is None else 'replaced','job':current,'plist':str(plist)}))\nexcept BaseException:\n if changed:\n  subprocess.run([ctl,'bootout','system/'+label],capture_output=True,timeout=12)\n  if old is None:\n   if plist.exists():plist.unlink()\n  else:\n   save(old)\n   if before['loaded']:subprocess.run([ctl,'bootstrap','system',str(plist)],capture_output=True,timeout=12)\n raise\n"
    command = (
        '/var/jb/usr/bin/python3 -c ' + shlex.quote(program) + ' '
        + ' '.join(shlex.quote(value) for value in
                   (bundle_id, registered_app, cryptex_app))
    )
    result = ssh(command, timeout=100)
    report = json.loads(result.stdout)
    job = report.get('job', {})
    if not (job.get('pid') and
            job.get('program') == str(pathlib.Path(registered_app) / 'TRCallMonitor')):
        raise RuntimeError('TrollRecorder launchd service did not stay running')
    log('verified TrollRecorder launchd service pid ' + str(job['pid']))


def register_and_link(bundle_id: str, executable: str, app_name: str, mount: str,
                      payload_bytes: int = 0,
                      launch_policy: str = "REQUIRED") -> str:
    cryptex_app = f"{mount}/Applications/{app_name}"
    # The Procursus backup is intentionally only a recovery copy.  After a
    # reboot its ad-hoc CDHash may no longer be covered by any active loadable
    # trust cache even though the persistent appregistrard Cryptex is healthy.
    # Prefer the executable from the currently mounted, sealed Cryptex and use
    # the backup only when that generation is unavailable.
    resolver = ssh(
        "for p in "
        f"{MOUNT_ROOT}/codes.rambo.research.appregistrard.*/usr/bin/appregistrard; do "
        "m=${p%/usr/bin/appregistrard}; "
        "if [ -x \"$p\" ] && mount | grep -Fq \" on $m (\"; then echo \"$p\"; fi; "
        "done",
        timeout=30, check=False,
    )
    mounted_helpers = [
        line.strip() for line in resolver.stdout.decode("utf-8", "replace").splitlines()
        if line.strip()
    ]
    registrar = mounted_helpers[-1] if mounted_helpers else None
    # Some SRD boot sets intentionally carry only the rootless uicache client;
    # the dedicated appregistrard Cryptex is not an invariant dependency.
    use_uicache = registrar is None
    # Both OS generations use the same durable MCM registration model. Darwin
    # 25 reaches it through appregistrard's bounded CoreServices/MCM-copy path
    # because InstallCoordination can deadlock there; Darwin 26+ retains the
    # coordinated path used by the stable iPhone configuration.
    kernel = ssh("uname -r", timeout=15, check=False).stdout.decode().strip()
    try:
        kernel_major = int(kernel.split(".", 1)[0])
    except (ValueError, IndexError):
        kernel_major = 0
    # InstallCoordination can deadlock while replacing the same bundle after
    # several rapid research builds. Explicitly retire the prior LS bundle
    # registration first. Its data container and the older mounted Cryptex are
    # untouched, while the following coordinated registration gets a clean
    # transaction instead of waiting indefinitely on the stale app record.
    listing = ssh("/var/jb/usr/bin/uicache -l 2>/dev/null", timeout=30, check=False)
    existing = None
    prefix = bundle_id + " : "
    for line in listing.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith(prefix):
            existing = line[len(prefix):].strip()
            break
    if existing:
        log(f"unregistering prior {bundle_id} bundle before coordinated replacement")
        retired = ssh((
            f"/var/jb/usr/bin/uicache -u {shlex.quote(existing)}"
            if use_uicache else
            # A Cryptex replacement necessarily retires the old mount before
            # LaunchServices forgets its bundle URL. The research registrar's
            # explicit allow-missing mode removes that stale record without
            # treating the vanished payload as an integrity failure.
            f"if [ -e {shlex.quote(existing)} ]; then "
            f"{shlex.quote(registrar)} unregister {shlex.quote(existing)}; "
            f"else {shlex.quote(registrar)} unregister --allow-missing {shlex.quote(existing)}; fi"
        ), timeout=60, check=False)
        if retired.returncode != 0:
            detail = (retired.stderr or retired.stdout).decode("utf-8", "replace").strip()
            raise RuntimeError("could not retire prior app registration: " + detail)
    # iOS 27 rejects the old direct LSApplicationWorkspace dictionary API.
    # Use InstallCoordination while the cryptex-backed SRD installd hook is
    # active; the hook supplies lenient verification and the mounted cryptex
    # supplies executable trust. The appregistrard inbox marker makes the hook
    # skip redundant personalization.
    # A large, tool-rich app can take several minutes to materialize in its
    # MCM bundle.  Starting InstallCoordination and then launching the fallback
    # after a short timeout creates two competing copies.  For payloads above
    # 512 MiB, select the same bounded MCM path up front and size its timeout
    # from reviewed payload bytes (never from untrusted shell input).
    large_bundle = payload_bytes > 512 * 1024 * 1024
    register_command = app_registration_command(
        registrar, cryptex_app, kernel_major, fallback=large_bundle
    )
    fallback_used = large_bundle
    register_timeout = (
        min(900, max(180, 180 + payload_bytes // (4 * 1024 * 1024)))
        if large_bundle else 180
    )
    try:
        coordinated = ssh(register_command, timeout=register_timeout, check=False)
    except subprocess.TimeoutExpired:
        # Keep the destination model identical after an IPC timeout: fall back
        # to appregistrard's MCM-copy implementation when the helper exists,
        # rather than demoting the app to a private Cryptex LaunchServices URL.
        fallback_used = True
        fallback = app_registration_command(
            registrar, cryptex_app, kernel_major, fallback=True
        )
        coordinated = ssh(fallback, timeout=90, check=False)
    # installcoordinationd can report a non-zero status after it has already
    # committed an update and materialized the new bundle. Do not turn that
    # successful update into a permanently stale keeper policy. We verify the
    # resulting MCM bundle below and only accept this case when both the main
    # executable and Info.plist exactly match the current Cryptex payload.
    coordination_error = None
    if coordinated.returncode != 0:
        coordination_error = (
            coordinated.stderr.decode("utf-8", "replace").strip()
            or coordinated.stdout.decode("utf-8", "replace").strip()
            or f"exit status {coordinated.returncode}"
        )
        log(f"InstallCoordination returned {coordination_error}; verifying committed bundle")
    elif fallback_used:
        log("bounded MCM registration succeeded")

    finder = r'''import glob, os, plistlib, sys
bundle_id, app_name, executable=sys.argv[1:4]
found=[]
for container in glob.glob('/private/var/containers/Bundle/Application/*'):
    # InstallCoordination can leave the registered app as a dead symlink when
    # an older Cryptex generation is retired.  In that state scanning only
    # live Info.plist files cannot find the correct container.  MCM metadata is
    # authoritative and survives the retired mount.
    metadata=os.path.join(container,'.com.apple.mobile_container_manager.metadata.plist')
    try:
        with open(metadata,'rb') as f: value=plistlib.load(f).get('MCMMetadataIdentifier')
        if value==bundle_id:
            expected=os.path.join(container,app_name)
            # InstallCoordination may leave an icon-only placeholder here.
            if not os.path.isfile(os.path.join(expected,executable)): continue
            # MCM metadata timestamps can be preserved from an older duplicate
            # container. The directory itself changes when appregistrard copies
            # the currently registered bundle, so it is a better authority.
            score=os.path.getmtime(container)
            found.append((score,expected))
            continue
    except Exception: pass
    for info in glob.glob(os.path.join(container,'*.app','Info.plist')):
        try:
            with open(info,'rb') as f: value=plistlib.load(f).get('CFBundleIdentifier')
            if value==bundle_id and os.path.isfile(os.path.join(os.path.dirname(info),executable)):
                found.append((os.path.getmtime(info),os.path.dirname(info)))
        except Exception: pass
if found: print(max(found)[1])
'''
    encoded = __import__("base64").b64encode(finder.encode()).decode()
    command = (
        f"echo {shlex.quote(encoded)} | /var/jb/usr/bin/base64 -d | "
        f"/var/jb/usr/bin/python3 - {shlex.quote(bundle_id)} "
        f"{shlex.quote(app_name)} {shlex.quote(executable)}"
    )
    result = ssh(command, timeout=60)
    registered_app = result.stdout.decode().strip().splitlines()
    if not registered_app and registrar is not None and not fallback_used \
            and kernel_major != 25:
        # InstallCoordination occasionally reports success without committing
        # an MCM bundle during a same-identifier Cryptex replacement. Treat an
        # absent destination as a failed postcondition and retry through the
        # registrar's bounded MCM-copy path before retiring the new Cryptex.
        # This is safe to repeat because the fallback is keyed by the exact
        # bundle identifier and copies the currently mounted, verified app.
        fallback_used = True
        fallback = app_registration_command(
            registrar, cryptex_app, kernel_major, fallback=True
        )
        legacy = ssh(fallback, timeout=90, check=False)
        if legacy.returncode != 0:
            coordination_error = (
                legacy.stderr.decode("utf-8", "replace").strip()
                or legacy.stdout.decode("utf-8", "replace").strip()
                or f"fallback exit status {legacy.returncode}"
            )
        else:
            log("InstallCoordination produced no MCM bundle; bounded fallback succeeded")
        result = ssh(command, timeout=60)
        registered_app = result.stdout.decode().strip().splitlines()
    if not registered_app:
        if coordination_error:
            raise RuntimeError("InstallCoordination registration failed: " + coordination_error)
        if registrar is not None:
            raise RuntimeError(
                "appregistrard completed without materializing an MCM bundle"
            )
        # A non-containerized system app is valid, although most imports opt
        # into a bundle/data container through ResearchApp.plist defaults.
        if launch_policy == "REQUIRED":
            verify_foreground_launch(bundle_id, cryptex_app, executable)
        elif launch_policy == "CONTROLLED_EXIT":
            verify_foreground_launch(
                bundle_id, cryptex_app, executable,
                launch_validation="controlled-exit-v1")
        else:
            raise RuntimeError("unknown foreground launch policy")
        return cryptex_app
    registered_app, repaired_stale_copy = repair_stale_mcm_copy(
        registered_app[-1], cryptex_app, executable, registrar, kernel_major,
        command, register_timeout, fallback_used)
    if repaired_stale_copy and not fallback_used:
        # A non-zero coordination result is superseded only by the exact
        # executable and Info.plist proof from the bounded MCM repair.
        coordination_error = None
    fallback_used = repaired_stale_copy
    if registrar is not None:
        # The bounded copier deliberately materializes a complete MCM bundle,
        # but on current iOS 27 it can retain an older URL for the same bundle
        # identifier. That old URL may launch stale code even when the new MCM
        # copy is byte-identical to the Cryptex. Check the *path and bytes*.
        registered_app = reconcile_launch_services_url(
            bundle_id, registered_app, cryptex_app, executable, registrar,
            register_timeout)
    if coordination_error:
        log("InstallCoordination update was committed despite its non-zero status")
    # Keep InstallCoordination's materialized bundle in its MCM container.
    # Replacing it with a symlink into the read-only cryptex causes some apps to
    # abort when they compare their resolved bundle URL with the LS record.
    # The matching cryptex remains mounted and its trust cache authorizes the
    # identical executable bytes in this container.
    mark_trollstore_owned_mcm(bundle_id, registered_app, cryptex_app, executable)
    ensure_trollrecorder_srd_service(bundle_id, registered_app, cryptex_app)
    if launch_policy == "REQUIRED":
        verify_foreground_launch(bundle_id, registered_app, executable)
    elif launch_policy == "CONTROLLED_EXIT":
        verify_foreground_launch(
            bundle_id, registered_app, executable,
            launch_validation="controlled-exit-v1")
    else:
        raise RuntimeError("unknown foreground launch policy")
    return registered_app


def update_state(bundle_id: str, value: dict) -> None:
    state = {}
    if STATE.exists():
        try: state = json.loads(STATE.read_text())
        except Exception: state = {}
    state[bundle_id] = value
    atomic_json(STATE, state)
    remote = f"/var/jb/var/lib/crypstore/{bundle_id}.json"
    ssh("mkdir -p /var/jb/var/lib/crypstore", timeout=30)
    remote_write(remote + ".tmp", (json.dumps(value, separators=(",", ":")) + "\n").encode())
    ssh(f"mv {shlex.quote(remote + '.tmp')} {shlex.quote(remote)}", timeout=30)


def suspend_removal_tombstone(bundle_id: str, job_id: str) -> str | None:
    """Temporarily supersede an earlier removal intent during reinstall.

    The keeper correctly removes MCM payloads covered by a tombstone. An
    explicit install of that same bundle is newer user intent, however, and
    previously raced the keeper: appregistrard created the icon and the keeper
    immediately removed it. Move, rather than delete, the tombstone until both
    registration and policy enrollment complete so a failed reinstall can
    restore the original removal intent.
    """
    if not BUNDLE_RE.fullmatch(bundle_id) or not JOB_RE.fullmatch(job_id):
        raise RuntimeError("invalid reinstall tombstone identity")
    root = "/var/jb/var/lib/crypstore/tombstones"
    target = f"{root}/{bundle_id}.json"
    staged = f"{root}/{bundle_id}.json.reinstalling-{job_id}"
    completed = ssh(
        f"mkdir -p {shlex.quote(root)}; "
        f"if [ -f {shlex.quote(target)} ]; then "
        f"mv {shlex.quote(target)} {shlex.quote(staged)} && "
        f"echo {shlex.quote(staged)}; fi",
        timeout=30, check=False,
    )
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", "replace").strip()
        raise RuntimeError("could not supersede removal tombstone: " + detail)
    paths = [line.strip() for line in completed.stdout.decode().splitlines()
             if line.strip()]
    return paths[-1] if paths else None


def finish_reinstall_tombstone(bundle_id: str, staged: str | None,
                               *, success: bool) -> None:
    """Commit a reinstall intent, or restore its prior tombstone on failure."""
    if staged is None:
        return
    target = f"/var/jb/var/lib/crypstore/tombstones/{bundle_id}.json"
    command = (
        f"rm -f {shlex.quote(staged)}"
        if success else
        f"if [ -f {shlex.quote(staged)} ] && "
        f"[ ! -e {shlex.quote(target)} ]; then "
        f"mv {shlex.quote(staged)} {shlex.quote(target)}; fi"
    )
    completed = ssh(command, timeout=30, check=False)
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).decode(
            "utf-8", "replace").strip()
        raise RuntimeError("could not finalize reinstall tombstone: " + detail)


def retire_live_registration(bundle_id: str) -> str | None:
    """Retire LaunchServices while the old Cryptex URL still exists.

    Older appregistrard builds correctly unregister a live bundle but reject a
    path after cryptexd retires its mount. Doing this before Cryptex replacement
    makes updates work across that ABI boundary and keeps the later
    ``--allow-missing`` path as recovery for already-stale records only.
    """
    listing = ssh("/var/jb/usr/bin/uicache -l 2>/dev/null", timeout=30, check=False)
    prefix = bundle_id + " : "
    matches = [line[len(prefix):].strip()
               for line in listing.stdout.decode("utf-8", "replace").splitlines()
               if line.startswith(prefix)]
    if not matches:
        return None
    if len(matches) != 1:
        raise RuntimeError(f"expected one prior {bundle_id} registration, found {len(matches)}")
    existing = matches[0]
    if not ssh(f"test -e {shlex.quote(existing)}", timeout=15, check=False).returncode == 0:
        # Leave an already-stale record to register_and_link(), whose current
        # research registrar has a deliberately explicit allow-missing mode.
        return None
    # Stop the live process while its vnode is still mounted. Replacing a
    # Cryptex underneath a running UIKit process causes a CODESIGNING/Invalid
    # Page termination and can leave SpringBoard with a termination assertion
    # that blocks the next launch until reboot.
    terminate = r'''import os,signal,subprocess,sys,time
prefix=os.path.realpath(sys.argv[1]).rstrip("/")+"/"
out=subprocess.run(["/bin/ps","-axo","pid=,command="],capture_output=True,text=True).stdout
for line in out.splitlines():
 try: pid_text,command=line.strip().split(None,1)
 except ValueError: continue
 if command.startswith(prefix):
  try: os.kill(int(pid_text),signal.SIGTERM)
  except OSError: pass
time.sleep(2)'''
    encoded = base64.b64encode(terminate.encode()).decode()
    ssh(f"echo {shlex.quote(encoded)} | /var/jb/usr/bin/base64 -d | "
        f"/var/jb/usr/bin/python3 - {shlex.quote(existing)}",
        timeout=30, check=False)
    resolver = ssh(
        "for p in "
        f"{MOUNT_ROOT}/codes.rambo.research.appregistrard.*/usr/bin/appregistrard; do "
        "m=${p%/usr/bin/appregistrard}; "
        "if [ -x \"$p\" ] && mount | grep -Fq \" on $m (\"; then echo \"$p\"; fi; done",
        timeout=30, check=False)
    registrars = [line.strip() for line in resolver.stdout.decode().splitlines() if line.strip()]
    command = (f"{shlex.quote(registrars[-1])} unregister {shlex.quote(existing)}"
               if registrars else f"/var/jb/usr/bin/uicache -u {shlex.quote(existing)}")
    retired = ssh(command, timeout=60, check=False)
    if retired.returncode:
        detail = (retired.stderr or retired.stdout).decode("utf-8", "replace").strip()
        raise RuntimeError("could not pre-retire live app registration: " + detail)
    return existing


def refresh_extension_registration(registered_app: str) -> None:
    """Publish complete PluginKit metadata from the trusted Control helper.

    InstallCoordination can commit the containing app on current iOS 27 while
    leaving extension registration without entitlements, team identity, or
    group-container mappings. NetworkExtension then records a provider that it
    immediately reports as "Update Required". The bundled Control helper has
    the complete, entitlement-aware LaunchServices registrar. Its historical
    marker is created only beside this exact MCM bundle for the duration of one
    registration call and is always removed again.
    """
    script = r'''import glob,json,os,plistlib,subprocess,sys
target=os.path.realpath(sys.argv[1])
allowed='/private/var/containers/Bundle/Application/'
if not target.startswith(allowed) or not target.endswith('.app') or not os.path.isdir(target):
 print(json.dumps({'status':'invalid_target'})); raise SystemExit(2)
helpers=[]
for info in glob.glob(allowed+'*/CrypStore.app/Info.plist'):
 try:
  with open(info,'rb') as f: bundle_id=plistlib.load(f).get('CFBundleIdentifier')
 except Exception: continue
 if bundle_id!='com.liquidsky.CrypStore': continue
 candidate=os.path.join(os.path.dirname(info),'trollstorehelper')
 if os.path.isfile(candidate) and os.access(candidate,os.X_OK): helpers.append(candidate)
if len(helpers)!=1:
 print(json.dumps({'status':'helper_count','count':len(helpers)})); raise SystemExit(3)
marker=os.path.join(os.path.dirname(target),'_CrypStore')
created=False
try:
 if not os.path.exists(marker):
  fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600); os.close(fd); created=True
 result=subprocess.run([helpers[0],'modify-registration',target,'User'],
                       stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60)
 print(json.dumps({'status':'complete','returncode':result.returncode}))
 raise SystemExit(result.returncode)
finally:
 if created:
  try: os.unlink(marker)
  except FileNotFoundError: pass
'''
    encoded = base64.b64encode(script.encode()).decode()
    command = (
        f"echo {shlex.quote(encoded)} | /var/jb/usr/bin/base64 -d | "
        f"/var/jb/usr/bin/python3 - {shlex.quote(registered_app)}"
    )
    result = ssh(command, timeout=90, check=False)
    if result.returncode:
        detail = (result.stderr or result.stdout).decode("utf-8", "replace").strip()
        raise RuntimeError("complete extension registration failed: " + detail[-2000:])
    try:
        report = json.loads(result.stdout.decode("utf-8", "replace").splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise RuntimeError("extension registrar returned no status") from error
    if report != {"status": "complete", "returncode": 0}:
        raise RuntimeError("extension registrar returned an invalid status")
    log("published complete entitlement-aware PluginKit registration")


def compatibility_intake(source: pathlib.Path, operation: str) -> None:
    # Release staging supplies the exact same engine next to this worker.
    # Source-tree runs resolve the canonical DeviceRuntime package.
    source_runtime = BASE.parents[2] / "DeviceRuntime"
    if source_runtime.is_dir():
        sys.path.insert(0, str(source_runtime))
    from zero_sky_compat import Environment
    from zero_sky_compat.integration import require_install_adapter
    result = ssh("/var/jb/usr/bin/python3 -c 'import sys; "
                 "sys.path.insert(0, \"/var/jb/usr/local/libexec\"); "
                 "import json; from dataclasses import asdict; "
                 "from zero_sky_compat.environment import detect; print(json.dumps(asdict(detect())))'",
                 timeout=120)
    environment = Environment(**json.loads(result.stdout))
    require_install_adapter(source, operation, INSTANCE / "compatibility", environment)


def process(job_id: str, request: dict) -> None:
    if request.get("operation") == "control-install":
        return process_control_install(job_id, request)
    if request.get("operation") == "link-install":
        return process_link_install(job_id, request)
    started = time.monotonic()
    timings: list[str] = []

    def stage(name: str, detail: str) -> None:
        if timings:
            previous_name, previous_started = timings[-1].rsplit("|", 1)
            timings[-1] = f"{previous_name}: {time.monotonic() - float(previous_started):.1f}s"
        timings.append(f"{name}|{time.monotonic()}")
        set_status(name, job_id, detail)
        log(f"{job_id}: {name} — {detail}")

    job_dir = JOBS / job_id
    if job_dir.exists():
        shutil.rmtree(job_dir)
    job_dir.mkdir(parents=True)
    atomic_json(job_dir / "request.json", request)
    ipa = job_dir / "input.ipa"
    stage("Receiving IPA", request.get("original_name", "IPA"))
    fetch_ipa(job_id, ipa)
    source_sha256 = verify_requested_ipa_sha256(ipa, request.get("source_sha256"))
    if normalize_ipa_archive(ipa):
        stage("Unwrapping package", "Normalized IPA transport/compression")
    stage("Checking host workspace", "Sizing IPA expansion and Cryptex staging")
    preflight_workspace(ipa)
    stage("Extracting package", "Validating the IPA payload")
    extract = job_dir / "extract"
    extract.mkdir()
    run(["/usr/bin/ditto", "-x", "-k", ipa, extract], timeout=300)
    apps = list((extract / "Payload").glob("*.app"))
    if len(apps) != 1:
        raise RuntimeError(f"IPA must contain exactly one app, found {len(apps)}")
    app = apps[0]
    launch_validation = requested_launch_validation(request, app)
    stage("Signing app", app.name)
    bundle_id, executable, app_name, components = sign_app(app, job_dir)
    launch_policy = foreground_launch_policy(app, launch_validation)
    # Generic install requests are also used by the Link-only host workflow.
    # Every reviewed first-party bundle needs the empty registrar marker
    # sealed into its signature before build_install_cryptex() admits it.
    if bundle_id in NATIVE_FIRST_PARTY:
        prepare_native_control(app, bundle_id)
    stage("Checking device workspace", "Sizing transactional Cryptex storage")
    preflight_device_workspace(app)
    stage("Retiring prior registration", bundle_id)
    retired_path = retire_live_registration(bundle_id)
    stage("Building & installing Cryptex", bundle_id)
    try:
        identifier, _ = build_install_cryptex(app, bundle_id, job_dir)
    except Exception:
        # If failure happened before cryptexd retired the old generation, put
        # its still-live registration back. This is best-effort rollback; the
        # original exception remains the authoritative failure evidence.
        if retired_path:
            ssh(f"test ! -e {shlex.quote(retired_path)} || "
                f"/var/jb/usr/bin/uicache -p {shlex.quote(retired_path)}",
                timeout=60, check=False)
        raise
    identity_policy = signed_identity_policy(app, bundle_id, identifier)
    stage("Locating Cryptex mount", identifier)
    mount = locate_mount(identifier, app_name)
    stage("Registering app", "appregistrard + InstallCoordination")
    registration_bytes = sum(
        path.stat().st_size for path in app.rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    staged_tombstone = suspend_removal_tombstone(bundle_id, job_id)
    try:
        # devicectl is reliable for replacing the already installed Control
        # application, while a fresh Link bundle has no MCM target to update
        # and can wait until devicectl's full deadline. Register Link from its
        # mounted, verified Cryptex through appregistrard instead.
        registered = (install_native_control(app, bundle_id, executable, job_dir)
                      if bundle_id == "com.liquidsky.CrypStore" else
                      register_and_link(bundle_id, executable, app_name, mount,
                                        registration_bytes,
                                        launch_policy=launch_policy))
        if components["extensions"]:
            stage("Refreshing app extensions",
                  f"{components['extensions']} PluginKit registration(s)")
            refresh_extension_registration(registered)
        state = {
            "bundle_id": bundle_id, "cryptex_identifier": identifier,
            "mount": mount, "registered_path": registered,
            "installed_at": int(time.time()), "source_name": request.get("original_name", ""),
            "source_sha256": source_sha256,
            "embedded_components": components,
            "foreground_launch": launch_policy,
            **identity_policy,
        }
        update_state(bundle_id, state)
    except Exception:
        finish_reinstall_tombstone(bundle_id, staged_tombstone, success=False)
        raise
    finish_reinstall_tombstone(bundle_id, staged_tombstone, success=True)
    if timings:
        previous_name, previous_started = timings[-1].rsplit("|", 1)
        timings[-1] = f"{previous_name}: {time.monotonic() - float(previous_started):.1f}s"
    elapsed = time.monotonic() - started
    set_status("Complete", job_id, f"Installed {bundle_id} in {elapsed:.1f}s")
    vpn_profile_notice = ""
    if components["packet_tunnel_providers"]:
        # NetworkExtension stores a signed-provider snapshot in the user's VPN
        # configuration. iOS deliberately owns that configuration, so editing
        # its private preference archive from a host worker would be unsafe and
        # non-reproducible. When an imported update changes the provider's
        # CDHash, removing and recreating only that app's VPN entry is the
        # supported recovery from Settings' otherwise opaque "Update Required".
        vpn_profile_notice = (
            "VPN profile note: iOS may retain the previous packet-tunnel "
            "provider identity after an app update. If Settings shows Update "
            "Required, delete only this app's VPN configuration and let the "
            "app add it again. 0-Sky does not alter VPN profiles automatically.\n"
        )
    remote_result(job_id, {
        "status": 0, "stdout": (f"0-Sky Control installed {bundle_id} in {elapsed:.1f}s.\n"
            + "\n".join(timings) + f"\n{registered}\n"
            + ("Embedded components preserved: "
               f"{components['extensions']} extension(s), "
               f"{components['frameworks']} framework(s), "
               f"{components['xpc_services']} XPC service(s), "
               f"{components['embedded_apps']} embedded app(s).\n")
            + f"Foreground launch verification: {launch_policy}.\n"
            + vpn_profile_notice),
        "stderr": "", "bundle_id": bundle_id,
        "embedded_components": components,
    })
    log(f"{job_id}: SUCCESS {bundle_id} ({elapsed:.1f}s)")
    cleanup_job_artifacts(job_dir)


def process_runtime_sync(job_id: str, request: dict) -> None:
    started = time.monotonic()
    package = request.get("package", "unknown package")
    set_status("Refreshing tweak trust cache", job_id, str(package))
    log(f"{job_id}: dynamic runtime synchronization for {package}")
    argv = [sys.executable, RUNTIME_SYNC, "--host", DEVICE_HOST,
            "--port", DEVICE_PORT or "0", "--key", DEVICE_KEY,
            "--udid", DEVICE_UDID, "--known-hosts", DEVICE_KNOWN_HOSTS,
            "--host-alias", DEVICE_HOST_ALIAS]
    package_names = [value.strip() for value in str(package).split(",") if value.strip()]
    if (not package_names or any(not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9.+-]{0,254}", value)
            for value in package_names)):
        raise RuntimeError("runtime sync request has an invalid package name")
    for value in sorted(set(package_names), key=str.casefold):
        argv.extend(["--package", value])
    completed = run(argv, timeout=1800, cwd=BASE, check=False)
    output = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    elapsed = time.monotonic() - started
    if completed.returncode:
        raise RuntimeError(f"runtime trust-cache sync failed ({completed.returncode}): {output[-4000:]}")
    set_status("Complete", job_id, f"Runtime synchronized in {elapsed:.1f}s")
    remote_result(job_id, {"status": 0, "stdout":
        f"Dynamic SRD runtime authorized installed tweaks in {elapsed:.1f}s.\n{output[-8000:]}",
        "stderr": "", "package": package})
    log(f"{job_id}: RUNTIME SYNC SUCCESS ({elapsed:.1f}s)")


def process_cryptex_uninstall(job_id: str, request: dict) -> None:
    """Permanently retire only a 0-Sky Control-owned per-app Cryptex.

    A tombstone prevents our keeper from restoring an app, but iOS can
    rematerialize a still-persistent app Cryptex on a later boot. Retiring the
    dedicated Cryptex is therefore the durable half of explicit app removal.
    """
    started = time.monotonic()
    bundle = request.get("bundle_identifier")
    identifier = request.get("cryptex_identifier")
    if not isinstance(bundle, str) or not BUNDLE_RE.fullmatch(bundle):
        raise RuntimeError("invalid bundle identifier in Cryptex retirement job")
    if not isinstance(identifier, str) or not CRYPTEX_RE.fullmatch(identifier):
        raise RuntimeError("refusing to retire a non-0-Sky Control Cryptex")
    set_status("Retiring removed app Cryptex", job_id, bundle)
    log(f"{job_id}: retiring {identifier} for removed {bundle}")
    completed = run([PYMOBILE, CRYPTEX_UNINSTALLER, identifier, DEVICE_UDID],
                    timeout=180, cwd=BASE, check=False)
    output = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    if completed.returncode:
        raise RuntimeError(
            f"Cryptex retirement failed ({completed.returncode}): {output[-4000:]}"
        )
    elapsed = time.monotonic() - started
    value = {}
    try:
        value = json.loads(STATE.read_text()).get(bundle, {})
    except Exception:
        pass
    if not isinstance(value, dict):
        value = {}
    value.update({"bundle_id": bundle, "bundle_identifier": bundle,
                  "cryptex_identifier": identifier, "persistence_mode": "removed",
                  "auto_repair_enabled": False,
                  "cryptex_retired_at": int(time.time())})
    update_state(bundle, value)
    set_status("Complete", job_id, f"Retired {bundle} in {elapsed:.1f}s")
    remote_result(job_id, {"status": 0, "stdout":
        f"Retired persistent 0-Sky Control source for {bundle} in {elapsed:.1f}s.\n{output[-4000:]}",
        "stderr": "", "bundle_id": bundle, "cryptex_identifier": identifier})
    log(f"{job_id}: CRYPTEX RETIREMENT SUCCESS {bundle} ({elapsed:.1f}s)")


def process_pair_verify(job_id: str, request: dict) -> None:
    """Complete Apple trust and bind the existing device bridge automatically."""
    if request.get("protocol_version") != 1:
        remote_result(job_id, {"status": 2, "stdout": "",
            "stderr": "0-Sky Link and Mac Bridge protocol versions are incompatible",
            "errorCode": "PROTOCOL_VERSION_MISMATCH",
            "expectedProtocol": 1, "receivedProtocol": request.get("protocol_version")})
        return
    set_status("Waiting for Apple Trust", job_id, "Unlock the device and approve Apple’s dialog")
    cancel_event = threading.Event()
    watcher_stop = threading.Event()

    def watch_cancel() -> None:
        cancel_path = REMOTE_SPOOL + "/" + job_id + "/cancel.json"
        while not watcher_stop.wait(1):
            try:
                probe = ssh(f"test -f {shlex.quote(cancel_path)}", timeout=10, check=False)
                if probe.returncode == 0:
                    cancel_event.set()
                    return
            except Exception:
                # A transport interruption is not user cancellation. The main
                # coordinator will classify it independently.
                continue

    watcher = threading.Thread(target=watch_cancel, name=f"pair-cancel-{job_id}", daemon=True)
    watcher.start()
    PAIRING_OPERATION_ACTIVE.set()
    recovered_wireless = False

    def publish_progress(value: dict) -> None:
        # The regular heartbeat thread forwards this structured state within
        # five seconds. No pairing credential is present in the progress model.
        atomic_json(PAIRING_LIVE, value)

    try:
        pairing_backend = host_module("apple_device_pairing")
        with PAIRING_CHECK_LOCK:
            coordinator = pairing_backend.MacPairingCoordinator(
                INSTANCE.parent.parent, timeout=900, cancel=cancel_event,
                progress=publish_progress)
            live = asyncio.run(coordinator.run(
                DEVICE_UDID,
                allow_pair=True,
                allow_host_enrollment=True,
            ))
            atomic_json(PAIRING_LIVE, live)
    finally:
        PAIRING_OPERATION_ACTIVE.clear()
        watcher_stop.set(); watcher.join(timeout=2)
    # A pair-verify request may have been queued while USB was attached and
    # claimed only after the user disconnected it. In that case the USB
    # coordinator reports USB_NOT_CONNECTED even though the already-enrolled
    # device is authenticated and reachable over Wi-Fi. Recover that trusted
    # relationship before publishing a failure or attempting remote_result,
    # because the latter itself must use the wireless SSH route.
    if not cancel_event.is_set() and live.get("status") != "verified":
        try:
            recovered = verified_network_pairing(pairing_backend)
            if recovered is not None:
                live = recovered
                recovered_wireless = True
                atomic_json(PAIRING_LIVE, live)
        except Exception as network_error:
            live["networkDiagnostic"] = (
                f"{type(network_error).__name__}: {network_error}")
            atomic_json(PAIRING_LIVE, live)
    if cancel_event.is_set() or live.get("errorCode") == "CANCELLED":
        set_status("Ready", None, "Pairing cancelled; trust records unchanged")
        remote_result(job_id, {"status": 130, "stdout": "", "stderr": "Pairing cancelled",
                               "errorCode": "CANCELLED"})
        return
    if live.get("status") != "verified":
        remote_result(job_id, {"status": 2, "stdout": "", "stderr": live.get("userMessage", "Pairing failed"),
                               "pairing": live})
        return
    if recovered_wireless:
        # The durable relationship/receipt was created during the USB phase.
        # Rebinding through the configured localhost usbmux route after the
        # cable is gone would turn success back into a transport error.
        bound = {"wireless": {"status": "ready",
                              "transport": live.get("transport", {}).get("type")}}
    else:
        pair_backend = host_module("pair")
        PAIRING_OPERATION_ACTIVE.set()
        try:
            bound = pair_backend.bind_verified_relationship(
                udid=DEVICE_UDID, ssh_key=DEVICE_KEY, host=DEVICE_HOST,
                port=DEVICE_PORT or "22", instance_name=INSTANCE.name,
                support=INSTANCE.parent.parent, pairing=live,
                write_device_marker=True, require_worker=False,
                provision_wireless=True, remote_port=DEVICE_REMOTE_PORT)
        finally:
            PAIRING_OPERATION_ACTIVE.clear()
    wireless = bound.get("wireless", {})
    if wireless.get("status") != "ready":
        PAIRING_OPERATION_ACTIVE.set()
        set_status("Testing Wireless", job_id,
                   "Disconnect the USB cable; 0-Sky will verify Wi-Fi automatically")
        transport_backend = host_module("apple_device_transport")
        pairing_backend = host_module("apple_device_pairing")
        _, fingerprint = pairing_backend.MacIdentity(INSTANCE.parent.parent).ensure()
        deadline = time.monotonic() + 180
        delay_index = 0
        verified = None
        while time.monotonic() < deadline and not cancel_event.is_set():
            manager = transport_backend.AppleDeviceTransportManager(INSTANCE.parent.parent)
            verified = asyncio.run(manager.verify_wireless(
                DEVICE_UDID, fingerprint, require_usb_absent=True,
                discovery_timeout=5, poll_interval=1))
            relationship = verified.get("relationship", {})
            state = ("WIRELESS_READY" if verified.get("status") == "ready" else
                     "WIRELESS_WAITING_FOR_DISCONNECT" if
                     verified.get("errorCode") == "USB_DISCONNECT_REQUIRED" else
                     "WIRELESS_DISCOVERING")
            live["wirelessPairing"] = {
                "wifiLockdown": ("VERIFIED" if verified.get("status") == "ready"
                                 else "ENABLED"),
                "remotePairing": ("VERIFIED" if relationship.get("remotePairingReady")
                                  else "NOT_REQUIRED"),
                "wirelessRSD": ("VERIFIED" if relationship.get("wirelessRSDVerified")
                                else "PENDING"),
                "usbAvailable": bool(relationship.get("usbAvailable")),
                "wifiAvailable": bool(relationship.get("wifiAvailable")),
            }
            # Keep result/status IPC comfortably below the bridge's bounded
            # response limit during a full three-minute disconnect wait.
            live["events"] = (list(live.get("events") or []) + [{
                "timestamp": time.time(), "state_after": state,
                "result": "progress" if verified.get("status") != "ready" else "verified",
            }])[-64:]
            if verified.get("status") == "ready":
                live["transport"] = {
                    "usb": False, "type": verified.get("transport"),
                    "remoteServices": {
                        "status": "PASS" if relationship.get("wirelessRSDVerified") else "NOT_REQUIRED",
                        "provider": verified.get("transport"),
                    },
                }
                atomic_json(PAIRING_LIVE, live)
                break
            atomic_json(PAIRING_LIVE, live)
            if verified.get("errorCode") == "USB_DISCONNECT_REQUIRED":
                time.sleep(1)
            else:
                delays = (1, 2, 5, 10, 30)
                time.sleep(delays[min(delay_index, len(delays) - 1)])
                delay_index += 1
        if cancel_event.is_set():
            PAIRING_OPERATION_ACTIVE.clear()
            set_status("Ready", None, "Pairing cancelled; trust records unchanged")
            remote_result(job_id, {"status": 130, "stdout": "", "stderr": "Pairing cancelled",
                                   "errorCode": "CANCELLED"})
            return
        if not verified or verified.get("status") != "ready":
            PAIRING_OPERATION_ACTIVE.clear()
            remote_result(job_id, {"status": 3, "stdout": "",
                "stderr": "USB pairing is verified and Wi-Fi is configured, but wireless verification requires disconnecting USB.",
                "errorCode": (verified or {}).get("errorCode", "WIRELESS_NOT_DISCOVERED"),
                "pairing": live})
            return
        PAIRING_OPERATION_ACTIVE.clear()
    set_status("Trusted Mac Verified", job_id, DEVICE_UDID)
    remote_result(job_id, {"status": 0,
                           "stdout": "Trusted Mac VERIFIED: USB primary, Wi-Fi fallback",
                           "stderr": "",
                           "pairing": live})


def process_crane_container_cleanup(job_id: str, request: dict) -> None:
    """Delete one verified orphan directory after Crane removed its metadata."""
    package = request.get("package")
    bundle_id = request.get("bundle_id")
    container_id = request.get("container_id")
    data_root = request.get("data_root")
    if package != "com.opa334.crane":
        raise RuntimeError("unsupported Crane cleanup package")
    if not isinstance(bundle_id, str) or not BUNDLE_RE.fullmatch(bundle_id):
        raise RuntimeError("invalid Crane cleanup application")
    if (not isinstance(container_id, str) or not re.fullmatch(
            r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}", container_id)):
        raise RuntimeError("invalid Crane cleanup container")
    if (not isinstance(data_root, str) or not re.fullmatch(
            r"/(?:private/)?var/mobile/Containers/Data/Application/"
            r"[0-9A-Fa-f-]{36}", data_root)):
        raise RuntimeError("invalid Crane cleanup data root")
    payload = {
        "bundle_id": bundle_id,
        "container_id": container_id,
        "data_root": data_root,
    }
    program = r'''import json,os,pathlib,plistlib,shutil,stat,sys,time
c=json.loads(sys.argv[1]);bundle=c["bundle_id"];identifier=c["container_id"]
root=pathlib.Path(c["data_root"]);base=pathlib.Path("/private/var/mobile/Containers/Data/Application")
resolved=pathlib.Path(os.path.realpath(root))
if resolved.parent!=base or root.is_symlink() or not root.is_dir():raise SystemExit("unsafe MCM data root")
metadata=root/".com.apple.mobile_container_manager.metadata.plist"
if metadata.is_symlink() or not metadata.is_file():raise SystemExit("MCM ownership metadata missing")
if plistlib.loads(metadata.read_bytes()).get("MCMMetadataIdentifier")!=bundle:raise SystemExit("MCM ownership mismatch")
prefs=pathlib.Path("/var/mobile/Library/Preferences/com.opa334.craneprefs.plist")
value=plistlib.loads(prefs.read_bytes()) if prefs.is_file() and not prefs.is_symlink() else {}
settings=value.get("appSettings_"+bundle,{}) if isinstance(value,dict) else {}
active=settings.get("activeContainer","DEFAULT") if isinstance(settings,dict) else "DEFAULT"
if not isinstance(active,str) or active.upper()==identifier:raise SystemExit("Crane container is still active")
target=root/"Library/___Crane_Containers"/identifier
if target.parent!=root/"Library/___Crane_Containers":raise SystemExit("unsafe Crane target")
if target.exists() or target.is_symlink():
 info=target.lstat()
 if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):raise SystemExit("unsafe Crane container type")
 shutil.rmtree(target)
if target.exists() or target.is_symlink():raise SystemExit("Crane container remains")
print(json.dumps({"bundle_id":bundle,"container_id":identifier,"removed":True,"path":str(target)},sort_keys=True))
'''
    completed = ssh(
        "/var/jb/usr/bin/python3 -c " + shlex.quote(program) + " " +
        shlex.quote(json.dumps(payload, sort_keys=True)), timeout=30, check=False)
    if completed.returncode:
        raise RuntimeError("paired Crane cleanup failed: " +
                           completed.stderr.decode("utf-8", "replace")[-500:])
    try:
        evidence = json.loads(completed.stdout.decode("utf-8", "replace").splitlines()[-1])
    except (IndexError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("paired Crane cleanup returned invalid evidence") from error
    set_status("Ready", None, "Crane container cleanup complete")
    remote_result(job_id, {"status": 0, "result": "PASS", "stage": "CLEANUP",
                           "stdout": "Crane container files removed", "stderr": "",
                           "evidence": evidence, "rollback": "NOT_NEEDED"})


def process_crane_target_handoff(job_id: str, request: dict) -> None:
    """Atomically update bounded pre-main handoffs in verified MCM roots."""
    if request.get("package") != "com.opa334.crane":
        raise RuntimeError("unsupported Crane handoff package")
    handoffs = request.get("handoffs")
    if not isinstance(handoffs, list) or not handoffs or len(handoffs) > 64:
        raise RuntimeError("invalid Crane handoff transaction")
    seen = set()
    for item in handoffs:
        if not isinstance(item, dict) or set(item) != {"bundle_id", "data_root", "active"}:
            raise RuntimeError("invalid Crane handoff entry")
        bundle = item["bundle_id"]
        root = item["data_root"]
        active = item["active"]
        if (not isinstance(bundle, str) or not BUNDLE_RE.fullmatch(bundle) or bundle in seen or
                not isinstance(root, str) or not re.fullmatch(
                    r"/private/var/mobile/Containers/Data/Application/"
                    r"[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", root) or
                (active != "DEFAULT" and (not isinstance(active, str) or not re.fullmatch(
                    r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}", active)))):
            raise RuntimeError("unsafe Crane handoff entry")
        seen.add(bundle)
    program = r'''import json,os,pathlib,plistlib,stat,sys
items=json.loads(sys.argv[1]);base=pathlib.Path("/private/var/mobile/Containers/Data/Application")
states=[]
def write_value(target,value,uid,gid):
 target.parent.mkdir(parents=True,exist_ok=True);os.chmod(target.parent,0o700);os.chown(target.parent,uid,gid)
 if value is None:
  target.unlink(missing_ok=True);return
 tmp=target.with_name(target.name+".%d.tmp"%os.getpid())
 fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
 try:
  os.write(fd,value);os.fsync(fd);os.fchmod(fd,0o600);os.fchown(fd,uid,gid)
 finally:os.close(fd)
 os.replace(tmp,target)
 dfd=os.open(target.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0));os.fsync(dfd);os.close(dfd)
try:
 for item in items:
  root=pathlib.Path(item["data_root"]);resolved=pathlib.Path(os.path.realpath(root))
  if resolved.parent!=base or root.is_symlink() or not root.is_dir():raise RuntimeError("unsafe MCM data root")
  metadata=root/".com.apple.mobile_container_manager.metadata.plist"
  if metadata.is_symlink() or not metadata.is_file():raise RuntimeError("MCM ownership metadata missing")
  if plistlib.loads(metadata.read_bytes()).get("MCMMetadataIdentifier")!=item["bundle_id"]:raise RuntimeError("MCM ownership mismatch")
  target=root/"Library/0Sky/Crane/active-container"
  if target.exists() and (target.is_symlink() or not target.is_file() or target.stat().st_size>128):raise RuntimeError("unsafe prior Crane handoff")
  prior=target.read_bytes() if target.is_file() else None
  if prior is not None:
   text=prior.decode("ascii").strip()
   import re
   if not re.fullmatch(r"[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}",text):raise RuntimeError("invalid prior Crane handoff")
  info=root.stat();states.append((target,prior,info.st_uid,info.st_gid,item))
 for target,prior,uid,gid,item in states:
  value=None if item["active"]=="DEFAULT" else (item["active"]+"\n").encode("ascii")
  write_value(target,value,uid,gid)
except Exception:
 for target,prior,uid,gid,item in reversed(states):
  try:write_value(target,prior,uid,gid)
  except Exception:pass
 raise
print(json.dumps([{"bundle_id":item["bundle_id"],"state":"default" if item["active"]=="DEFAULT" else "isolated"} for target,prior,uid,gid,item in states],sort_keys=True))
'''
    completed = ssh(
        "/var/jb/usr/bin/python3 -c " + shlex.quote(program) + " " +
        shlex.quote(json.dumps(handoffs, sort_keys=True)), timeout=45, check=False)
    if completed.returncode:
        raise RuntimeError("paired Crane handoff failed: " +
                           completed.stderr.decode("utf-8", "replace")[-500:])
    try:
        evidence = json.loads(completed.stdout.decode("utf-8", "replace").splitlines()[-1])
    except (IndexError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("paired Crane handoff returned invalid evidence") from error
    set_status("Ready", None, "Crane application targets updated")
    remote_result(job_id, {"status": 0, "result": "PASS", "stage": "HANDOFF",
                           "stdout": "Crane target handoffs committed", "stderr": "",
                           "evidence": evidence, "rollback": "NOT_NEEDED"})


def process_one() -> bool:
    for job_id in list_jobs():
        request = None
        try:
            # A device at ENOSPC may reject even the tiny result.json write.
            # Never reclaim and execute that already-finished job again.  Keep
            # its terminal result on the Mac and retry only the result write.
            if pending_result_path(job_id).is_file():
                return flush_deferred_result(job_id)
            request = claim_job(job_id)
            if request is None:
                continue
            if (request.get("operation") == "pair-verify" and
                    int(request.get("created_at", 0) or 0) < int(time.time()) - 240):
                remote_result(job_id, {"status": 130, "stdout": "",
                    "errorCode": "SUPERSEDED",
                    "stderr": "This abandoned pairing request was replaced; start Wi-Fi verification again."})
                return True
            if request.get("operation") == "runtime-sync":
                process_runtime_sync(job_id, request)
            elif request.get("operation") == "uninstall-cryptex":
                process_cryptex_uninstall(job_id, request)
            elif request.get("operation") == "pair-verify":
                process_pair_verify(job_id, request)
            elif request.get("operation") == "crane-container-cleanup":
                process_crane_container_cleanup(job_id, request)
            elif request.get("operation") == "crane-target-handoff":
                process_crane_target_handoff(job_id, request)
            else:
                process(job_id, request)
        except Exception as error:
            PAIRING_OPERATION_ACTIVE.clear()
            detail = traceback.format_exc()
            log(f"{job_id}: FAILED {error}")
            set_status("Failed", job_id, str(error))
            (JOBS / job_id).mkdir(parents=True, exist_ok=True)
            (JOBS / job_id / "error.log").write_text(detail, encoding="utf-8")
            failure = {
                "status": 125, "stdout": "",
                "stderr": f"0-Sky Mac worker failed: {error}",
                "rollback": error.rollback if isinstance(error, ControlInstallFailed) else "UNKNOWN",
            }
            try:
                remote_result(job_id, failure)
            except Exception as report_error:
                log(f"{job_id}: could not report failure: {report_error}")
                defer_remote_result(job_id, failure)
            cleanup_job_artifacts(JOBS / job_id)
        return True
    return False


def main() -> int:
    global DEVICE_UDID
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--interval", type=float, default=2.0)
    args = parser.parse_args()
    DEVICE_UDID = resolve_device_udid()
    if (not DEVICE_HOST or not DEVICE_PORT or not DEVICE_PORT.isdecimal()
            or not 1 <= int(DEVICE_PORT) <= 65535
            or not DEVICE_KEY.is_file() or not DEVICE_KNOWN_HOSTS.is_file()
            or DEVICE_KNOWN_HOSTS.is_symlink()):
        parser.error("exact device host, port, private SSH key, and pinned known-hosts file are required")
    for path in (JOBS, LOGS): path.mkdir(parents=True, exist_ok=True)
    with LOCK.open("w") as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return 0
        log(f"worker started for {DEVICE_HOST} ({DEVICE_UDID})")
        heartbeat = threading.Thread(target=heartbeat_loop, name="crypstore-heartbeat", daemon=True)
        heartbeat.start()
        base_interval = max(args.interval, 2.0)
        poll_delay = base_interval
        try:
            while True:
                try:
                    processed = process_one()
                    poll_delay = base_interval
                except Exception as error:
                    poll_delay = min(60, max(5, poll_delay * 2))
                    log(f"poll failed: {error}; retrying in {poll_delay}s")
                    processed = False
                if args.once: return 0
                if not processed:
                    set_status("Ready", None, "Waiting for an IPA")
                    STOP_HEARTBEAT.wait(poll_delay)
        finally:
            STOP_HEARTBEAT.set()
            heartbeat.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
