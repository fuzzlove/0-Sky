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
import subprocess
import sys
import threading
import time
import traceback
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
LDID = pathlib.Path(os.environ.get("CRYPSTORE_LDID") or shutil.which("ldid") or "ldid")
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
    if '"' in str(DEVICE_KNOWN_HOSTS) or "\n" in str(DEVICE_KNOWN_HOSTS):
        raise RuntimeError("device SSH known-hosts path contains unsupported characters")
    return [
        "/usr/bin/ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f'UserKnownHostsFile="{DEVICE_KNOWN_HOSTS}"',
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"HostKeyAlias={DEVICE_HOST_ALIAS}",
        "-o", "IdentitiesOnly=yes", "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        # The configured route may be a CoreDevice forward whose tunnel address
        # rotates after Apple-session refresh. Avoid retaining a multiplexed
        # master across that authenticated transport transition.
        "-o", "ControlMaster=no", "-o", "ControlPersist=no",
        "-o", f"ControlPath={control_path(transport)}", "-i", str(DEVICE_KEY),
        "-p", str(port), f"{DEVICE_USER}@{host}",
    ]


SSH_BASE = ssh_base_for(DEVICE_HOST, DEVICE_PORT or "22", "configured")

STATUS_LOCK = threading.Lock()
SSH_LOCK = threading.RLock()
STATUS = {"stage": "Ready", "job_id": None, "detail": "Waiting for an IPA"}
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
            result.append((ssh_base_for(bonjour, "22", "bonjour"),
                           control_path("bonjour"), "bonjour"))
        result.append((ssh_base_for(f"{DEVICE_UDID}.coredevice.local", "22", "wireless"),
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
    ssh(f"mv {shlex.quote(temporary)} {shlex.quote(REMOTE_HEARTBEAT)}", timeout=30)


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


def list_jobs() -> list[str]:
    command = (
        f"mkdir -p {shlex.quote(REMOTE_SPOOL)}; "
        f"for d in {shlex.quote(REMOTE_SPOOL)}/*; do "
        "[ -d \"$d\" ] || continue; [ -f \"$d/result.json\" ] && continue; "
        "if [ -f \"$d/request.json\" ] || [ -f \"$d/processing.json\" ]; "
        "then echo \"$d/request.json\"; fi; done 2>/dev/null"
    )
    result = ssh(command, timeout=30, check=False)
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
    result = ssh(command, timeout=30, check=False)
    if not result.stdout.strip():
        return None
    request = json.loads(result.stdout)
    if (request.get("job_id") != job_id or request.get("operation") not in
            ("install", "runtime-sync", "uninstall-cryptex", "pair-verify")):
        raise RuntimeError("invalid queued request")
    return request


def fetch_ipa(job_id: str, destination: pathlib.Path) -> None:
    root = f"{REMOTE_SPOOL}/{job_id}"
    result = ssh(f"cat {shlex.quote(root + '/input.ipa')}", timeout=600)
    destination.write_bytes(result.stdout)
    if destination.stat().st_size < 256:
        raise RuntimeError("queued IPA is empty")


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
    try:
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > MAX_IPA_ENTRIES:
                raise RuntimeError("IPA contains too many archive entries")
            if archive.testzip() is not None:
                raise RuntimeError("IPA ZIP data is damaged")
    except zipfile.BadZipFile as error:
        raise RuntimeError(f"selected IPA ZIP is invalid: {error}") from error
    return unwrapped


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
    completed = run([LDID, "-e", binary], timeout=30, check=False)
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


def codesign(target: pathlib.Path, entitlements: pathlib.Path | None = None) -> None:
    argv = [
        "/usr/bin/codesign", "--force", "--sign", "-", "--timestamp=none",
        "--generate-entitlement-der",
    ]
    if entitlements:
        argv += ["--entitlements", entitlements]
    argv.append(target)
    run(argv, timeout=120)


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

    # Sign every bare Mach-O first, then nested code bundles from the inside out,
    # and finally the outer app so its CodeResources seals the finished tree.
    for binary in sorted(binaries, key=lambda value: len(value.parts), reverse=True):
        codesign(binary, entitlement_map[binary])

    for bundle in sorted(bundles, key=lambda value: len(value.parts), reverse=True):
        executable = bundle_executable(bundle)
        codesign(bundle, entitlement_map.get(executable) if executable else None)
    codesign(app, entitlement_map.get(main))
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=2", app], timeout=120)
    assert_no_transient_markers(app)
    return bundle_id, executable_name, app.name, components


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
        completed = run_process_group(
            [cryptex_dir / "build_and_install.sh"], timeout=300,
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
                             executable: str, *, observation_seconds: float = 8.0) -> None:
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


def register_and_link(bundle_id: str, executable: str, app_name: str, mount: str,
                      payload_bytes: int = 0) -> str:
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
bundle_id, app_name=sys.argv[1:3]
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
            if value==bundle_id: found.append((os.path.getmtime(info),os.path.dirname(info)))
        except Exception: pass
if found: print(max(found)[1])
'''
    encoded = __import__("base64").b64encode(finder.encode()).decode()
    command = (
        f"echo {shlex.quote(encoded)} | /var/jb/usr/bin/base64 -d | "
        f"/var/jb/usr/bin/python3 - {shlex.quote(bundle_id)} {shlex.quote(app_name)}"
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
        verify_foreground_launch(bundle_id, cryptex_app, executable)
        return cryptex_app
    registered_app = registered_app[-1]
    if fallback_used and registrar is not None:
        # The bounded copier deliberately materializes a complete MCM bundle,
        # but on current iOS 27 it does not always publish that final URL to
        # LaunchServices.  Complete the transaction from the already copied
        # MCM path; unlike starting from the Cryptex URL, this phase does not
        # race a second long copy and preserves the full app icon/identity.
        listing = ssh("/var/jb/usr/bin/uicache -l 2>/dev/null", timeout=30,
                      check=False).stdout.decode("utf-8", "replace")
        expected = bundle_id + " : "
        if not any(line.startswith(expected) for line in listing.splitlines()):
            publish = ssh(
                f"{shlex.quote(registrar)} register --path "
                f"{shlex.quote(registered_app)} --absolute",
                timeout=register_timeout, check=False,
            )
            if publish.returncode != 0:
                detail = (publish.stderr or publish.stdout).decode(
                    "utf-8", "replace").strip()
                raise RuntimeError("MCM bundle was copied but icon registration failed: " + detail)
            result = ssh(command, timeout=60)
            refreshed = result.stdout.decode().strip().splitlines()
            if refreshed:
                registered_app = refreshed[-1]
            listing = ssh("/var/jb/usr/bin/uicache -l 2>/dev/null", timeout=30,
                          check=False).stdout.decode("utf-8", "replace")
            if not any(line.startswith(expected) for line in listing.splitlines()):
                raise RuntimeError("MCM publication completed without an exact LaunchServices record")
            log("published large MCM bundle to LaunchServices")
    if coordination_error:
        match = ssh(
            f"cmp -s {shlex.quote(registered_app + '/' + executable)} "
            f"{shlex.quote(cryptex_app + '/' + executable)} && "
            f"cmp -s {shlex.quote(registered_app + '/Info.plist')} "
            f"{shlex.quote(cryptex_app + '/Info.plist')}",
            timeout=30, check=False,
        )
        if match.returncode != 0:
            raise RuntimeError(
                "InstallCoordination registration failed and the materialized bundle "
                "does not match the newly installed Cryptex: " + coordination_error
            )
        log("InstallCoordination update was committed despite its non-zero status")
    # Keep InstallCoordination's materialized bundle in its MCM container.
    # Replacing it with a symlink into the read-only cryptex causes some apps to
    # abort when they compare their resolved bundle URL with the LS record.
    # The matching cryptex remains mounted and its trust cache authorizes the
    # identical executable bytes in this container.
    verify_foreground_launch(bundle_id, registered_app, executable)
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


def process(job_id: str, request: dict) -> None:
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
    if normalize_ipa_archive(ipa):
        stage("Unwrapping package", "Removed gzip transport wrapper")
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
    stage("Signing app", app.name)
    bundle_id, executable, app_name, components = sign_app(app, job_dir)
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
        registered = register_and_link(
            bundle_id, executable, app_name, mount, registration_bytes
        )
        if components["extensions"]:
            stage("Refreshing app extensions",
                  f"{components['extensions']} PluginKit registration(s)")
            refresh_extension_registration(registered)
        state = {
            "bundle_id": bundle_id, "cryptex_identifier": identifier,
            "mount": mount, "registered_path": registered,
            "installed_at": int(time.time()), "source_name": request.get("original_name", ""),
            "embedded_components": components,
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
                provision_wireless=True)
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


def process_one() -> bool:
    for job_id in list_jobs():
        request = None
        try:
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
            else:
                process(job_id, request)
        except Exception as error:
            PAIRING_OPERATION_ACTIVE.clear()
            detail = traceback.format_exc()
            log(f"{job_id}: FAILED {error}")
            set_status("Failed", job_id, str(error))
            (JOBS / job_id).mkdir(parents=True, exist_ok=True)
            (JOBS / job_id / "error.log").write_text(detail, encoding="utf-8")
            try:
                remote_result(job_id, {
                    "status": 125, "stdout": "",
                    "stderr": f"0-Sky Control Mac worker failed: {error}",
                })
            except Exception as report_error:
                log(f"{job_id}: could not report failure: {report_error}")
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
