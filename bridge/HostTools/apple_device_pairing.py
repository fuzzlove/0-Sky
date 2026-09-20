#!/usr/bin/env python3
"""Shared iPhone/iPad Apple pairing state machine for the 0-Sky Mac bridge.

The backend uses pymobiledevice3's structured Python API.  Pairing and research
classification are deliberately independent: a successful Lockdown session
does not imply SRD eligibility, SSH access, or root access.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import dataclasses
import enum
import fcntl
import hashlib
import inspect
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import tempfile
import time
import uuid
from typing import Any, Callable, Protocol


PROTOCOL_VERSION = 1
BRIDGE_VERSION = "1.0.0"


class State(str, enum.Enum):
    IDLE = "IDLE"
    DISCOVERING_MAC = "DISCOVERING_MAC"
    MAC_FOUND = "MAC_FOUND"
    WAITING_FOR_USB = "WAITING_FOR_USB"
    DEVICE_DISCOVERED = "DEVICE_DISCOVERED"
    CHECKING_PAIRING = "CHECKING_PAIRING"
    ALREADY_PAIRED = "ALREADY_PAIRED"
    PAIRING_REQUIRED = "PAIRING_REQUIRED"
    REQUESTING_PAIR = "REQUESTING_PAIR"
    WAITING_FOR_TRUST = "WAITING_FOR_TRUST"
    VALIDATING_LOCKDOWN = "VALIDATING_LOCKDOWN"
    VERIFYING_DEVICE_IDENTITY = "VERIFYING_DEVICE_IDENTITY"
    VERIFYING_HOST_IDENTITY = "VERIFYING_HOST_IDENTITY"
    VERIFYING_SERVICES = "VERIFYING_SERVICES"
    CLASSIFYING_DEVICE = "CLASSIFYING_DEVICE"
    VERIFIED_TRUSTED = "VERIFIED_TRUSTED"
    NO_MAC = "NO_MAC"
    NO_USB_DEVICE = "NO_USB_DEVICE"
    MULTIPLE_DEVICES = "MULTIPLE_DEVICES"
    DEVICE_LOCKED = "DEVICE_LOCKED"
    TRUST_REQUIRED = "TRUST_REQUIRED"
    TRUST_DENIED = "TRUST_DENIED"
    PAIRING_FAILED = "PAIRING_FAILED"
    PAIR_RECORD_STALE = "PAIR_RECORD_STALE"
    LOCKDOWN_FAILED = "LOCKDOWN_FAILED"
    DEVICE_IDENTITY_MISMATCH = "DEVICE_IDENTITY_MISMATCH"
    HOST_IDENTITY_MISMATCH = "HOST_IDENTITY_MISMATCH"
    HOST_CONFIRMATION_REQUIRED = "HOST_CONFIRMATION_REQUIRED"
    TRANSPORT_FAILED = "TRANSPORT_FAILED"
    BACKEND_UNAVAILABLE = "BACKEND_UNAVAILABLE"
    PROTOCOL_VERSION_MISMATCH = "PROTOCOL_VERSION_MISMATCH"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


ERRORS = {
    "MAC_NOT_FOUND": ("0-Sky Mac Bridge is unavailable.", "Open 0-Sky on the Mac and try again."),
    "BRIDGE_NOT_RUNNING": ("0-Sky Mac Bridge is not running.", "Open 0-Sky on the Mac; it starts automatically at login."),
    "USB_NOT_CONNECTED": ("Connect this iPhone or iPad to the Mac by USB.", "Keep the selected device connected and unlocked."),
    "MULTIPLE_DEVICES": ("More than one Apple device is connected.", "Select the intended device; 0-Sky will not choose the first device."),
    "DEVICE_LOCKED": ("Unlock this iPhone or iPad to continue.", "Unlock the device; verification resumes automatically."),
    "TRUST_REQUIRED": ("Approve Apple’s Trust This Computer dialog.", "Tap Trust and enter the device passcode if requested."),
    "TRUST_DENIED": ("Apple pairing was denied.", "Reconnect the device and choose Pair With Mac when ready."),
    "PAIR_REQUEST_FAILED": ("Apple pairing could not be completed.", "Keep the device unlocked and connected, then retry."),
    "PAIR_RECORD_STALE": ("The saved pairing is stale.", "Choose Repair Trusted Mac Pairing; only this device record is renewed."),
    "LOCKDOWN_VALIDATION_FAILED": ("Apple pairing could not be authenticated.", "Unlock the selected device and repair its pairing."),
    "DEVICE_IDENTITY_MISMATCH": ("A different device answered the request.", "Disconnect other devices and select the intended device again."),
    "HOST_IDENTITY_MISMATCH": ("This is not the enrolled 0-Sky Mac identity.", "Use the enrolled Mac or explicitly reset 0-Sky host enrollment."),
    "HOST_ENROLLMENT_REQUIRED": ("Confirm this 0-Sky Mac before enrollment.", "Review the Mac name and fingerprint, then choose Trust This Mac."),
    "REMOTE_SERVICE_UNAVAILABLE": ("Optional remote services are unavailable.", "Apple pairing remains separate; review Advanced Diagnostics."),
    "BACKEND_UNAVAILABLE": ("Apple device services are unavailable on this Mac.", "Restart 0-Sky Mac Bridge and reconnect USB."),
    "BACKEND_VERSION_MISMATCH": ("The Apple device backend version is incompatible.", "Update 0-Sky on the Mac."),
    "PROTOCOL_VERSION_MISMATCH": ("0-Sky versions cannot communicate.", "Update 0-Sky Link and 0-Sky Control together."),
    "TIMEOUT": ("Pairing timed out without changing trust.", "Keep the device unlocked and retry; Apple Trust remains user-controlled."),
    "CANCELLED": ("Pairing was cancelled.", "No pairing records were removed."),
}


class PairingFailure(RuntimeError):
    def __init__(self, code: str, state: State, diagnostic: str,
                 details: dict[str, Any] | None = None):
        super().__init__(diagnostic)
        self.code, self.state, self.diagnostic = code, state, diagnostic
        self.details = details or {}


@dataclasses.dataclass(frozen=True)
class Device:
    udid: str
    connection_type: str = "USB"
    name: str = "Apple Device"
    product_type: str = "UNKNOWN"
    product_version: str = "UNKNOWN"
    build_version: str = "UNKNOWN"


class AppleDeviceBackend(Protocol):
    async def list_devices(self) -> list[Device]: ...
    async def open_trusted_session(self, udid: str, *, pair: bool,
                                   timeout: float) -> tuple[Any, dict[str, Any]]: ...
    async def verify_remote_services(self, udid: str,
                                     timeout: float) -> dict[str, Any]: ...


class PymobiledeviceBackend:
    """Replaceable structured backend; no CLI output parsing."""

    @staticmethod
    async def _call(function, *args, **kwargs):
        # Current pymobiledevice3 exposes usbmux and Lockdown entry points as
        # native coroutine functions.  Calling one inside to_thread creates a
        # coroutine object in the worker thread; if the outer bounded timeout
        # cancels before the thread returns, that object is never awaited and
        # emits RuntimeWarning.  Dispatch coroutine functions directly on the
        # event loop and reserve the thread pool for genuinely synchronous
        # implementations/backends.
        if inspect.iscoroutinefunction(function):
            return await function(*args, **kwargs)
        value = await asyncio.to_thread(function, *args, **kwargs)
        return await value if inspect.isawaitable(value) else value

    async def list_devices(self) -> list[Device]:
        from pymobiledevice3.usbmux import list_devices
        from pymobiledevice3.lockdown import create_using_usbmux

        async def describe(item) -> Device:
            """Read picker metadata without initiating an Apple pair request.

            Lockdown's default-domain values are available before a new pairing
            ceremony.  ``autopair=False`` is therefore important: discovery may
            inspect the exact USB endpoint but must never create trust or raise
            Apple's consent dialog merely to populate a multi-device picker.
            A locked, old, or otherwise unreadable device remains selectable by
            its opaque hash and is represented with conservative placeholders.
            """
            udid = str(item.serial)
            fallback = Device(udid=udid, connection_type="USB")
            client = None
            try:
                client = await asyncio.wait_for(
                    self._call(
                        create_using_usbmux,
                        serial=udid,
                        autopair=False,
                        connection_type="USB",
                        pair_timeout=None,
                        label="0-Sky Mac Bridge Discovery",
                    ),
                    timeout=5,
                )
                values = getattr(client, "all_values", {})
                if not isinstance(values, dict):
                    return fallback
                # Bind metadata to the same usbmux endpoint.  Never decorate a
                # candidate with values returned by a different device.
                if str(values.get("UniqueDeviceID", "")) != udid:
                    return fallback
                return Device(
                    udid=udid,
                    connection_type="USB",
                    name=str(values.get("DeviceName") or "Apple Device"),
                    product_type=str(values.get("ProductType") or "UNKNOWN"),
                    product_version=str(values.get("ProductVersion") or "UNKNOWN"),
                    build_version=str(values.get("BuildVersion") or "UNKNOWN"),
                )
            except Exception:
                return fallback
            finally:
                if client is not None:
                    try:
                        value = client.close()
                        if inspect.isawaitable(value):
                            await value
                    except Exception:
                        pass

        usb_items = []
        for item in await self._call(list_devices):
            connection = str(getattr(item, "connection_type", "USB"))
            if connection.upper() != "USB":
                continue
            usb_items.append(item)
        # Describe endpoints concurrently under independent bounds so one
        # sleeping or legacy device cannot stall every other picker row.
        return list(await asyncio.gather(*(describe(item) for item in usb_items)))

    async def open_trusted_session(self, udid: str, *, pair: bool,
                                   timeout: float) -> tuple[Any, dict[str, Any]]:
        from pymobiledevice3.lockdown import create_using_usbmux
        client = await self._call(
            create_using_usbmux, serial=udid, autopair=pair,
            connection_type="USB", pair_timeout=timeout if pair else None,
            label="0-Sky Mac Bridge")
        try:
            # create_using_usbmux() returns a ready-to-use client and current
            # pymobiledevice3 has already called validate_pairing() inside
            # _handle_autopair, even when autopair=False. Calling it a second
            # time sends another StartSession on the same connection and real
            # devices answer LockdownError: SessionActive. Treat the client's
            # structured paired state as the postcondition. Only older
            # backends lacking that state receive one explicit validation.
            paired = getattr(client, "paired", None)
            valid = (await self._call(client.validate_pairing)
                     if paired is None else bool(paired))
            if not valid:
                raise PairingFailure("LOCKDOWN_VALIDATION_FAILED", State.LOCKDOWN_FAILED,
                                     "create_using_usbmux returned an unauthenticated client")
            values = await self._call(client.get_value)
            if not isinstance(values, dict):
                raise PairingFailure("LOCKDOWN_VALIDATION_FAILED", State.LOCKDOWN_FAILED,
                                     "Lockdown GetValue did not return a dictionary")
            return client, values
        except Exception:
            value = client.close()
            if asyncio.iscoroutine(value): await value
            raise

    async def verify_remote_services(self, udid: str,
                                     timeout: float = 15) -> dict[str, Any]:
        """Verify Apple's least-privileged native CoreDevice path.

        devicectl writes versioned JSON; stdout is never interpreted.  This is
        an independent capability result and cannot turn a failed Lockdown
        pairing into a success.
        """
        with tempfile.TemporaryDirectory(prefix="0sky-remote-service-") as directory:
            output = Path(directory) / "device.json"
            try:
                completed = await asyncio.to_thread(
                    subprocess.run,
                    ["/usr/bin/xcrun", "devicectl", "device", "info", "details",
                     "--device", udid, "--json-output", str(output)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=timeout, check=False)
            except (OSError, subprocess.TimeoutExpired) as error:
                return {"status": "FAIL", "provider": "CoreDevice",
                        "errorClass": type(error).__name__}
            if completed.returncode or not output.is_file():
                return {"status": "FAIL", "provider": "CoreDevice",
                        "errorClass": "REMOTE_SERVICE_UNAVAILABLE",
                        "exitCode": completed.returncode}
            try:
                record = json.loads(output.read_text()).get("result", {})
                properties = record.get("properties", {})
                connection = properties.get("connection", record.get("connectionProperties", {}))
                hardware = properties.get("hardware", record.get("hardwareProperties", {}))
                answered = str(hardware.get("udid", ""))
                if answered != udid:
                    return {"status": "FAIL", "provider": "CoreDevice",
                            "errorClass": "DEVICE_IDENTITY_MISMATCH"}
                paired = str(connection.get("pairingState", "")).lower() == "paired"
                connected = str(connection.get("state", connection.get("deviceState", ""))).lower() == "connected"
                return {"status": "PASS" if paired and connected else "FAIL",
                        "provider": "CoreDevice", "pairingState": connection.get("pairingState"),
                        "transportType": connection.get("transportType"),
                        "sessionState": connection.get("state", connection.get("deviceState")),
                        "identityMatched": True}
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                return {"status": "FAIL", "provider": "CoreDevice",
                        "errorClass": type(error).__name__}


class MacIdentity:
    def __init__(self, support: Path):
        self.path = support / "host-identity-ed25519.pem"
        self.support = support

    def ensure(self) -> tuple[Any, str]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.support.mkdir(parents=True, exist_ok=True)
        lock_path = self.support / ".host-identity.lock"
        with lock_path.open("a+b") as lock:
            os.chmod(lock_path, 0o600)
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            if self.path.exists():
                if self.path.is_symlink():
                    raise RuntimeError("host identity path must not be a symbolic link")
                os.chmod(self.path, 0o600)
                key = serialization.load_pem_private_key(self.path.read_bytes(), password=None)
                if not isinstance(key, Ed25519PrivateKey):
                    raise RuntimeError("host identity is not an Ed25519 private key")
            else:
                key = Ed25519PrivateKey.generate()
                temporary = self.support / f".host-identity-{os.getpid()}-{uuid.uuid4().hex}.tmp"
                encoded = key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(temporary, flags, 0o600)
                try:
                    with os.fdopen(descriptor, "wb", closefd=False) as stream:
                        stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
                finally:
                    os.close(descriptor)
                temporary.replace(self.path)
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
        public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(public).digest()).decode().rstrip("=")
        challenge = os.urandom(32)
        key.public_key().verify(key.sign(challenge), challenge)
        return key, fingerprint


class MacPairingCoordinator:
    def __init__(self, support: Path, backend: AppleDeviceBackend | None = None,
                 *, timeout: float = 300, poll_interval: float = 2,
                 cancel: asyncio.Event | None = None,
                 progress: Callable[[dict[str, Any]], None] | None = None):
        self.support = support.expanduser().resolve()
        self.backend = backend or PymobiledeviceBackend()
        self.timeout, self.poll_interval = timeout, poll_interval
        self.cancel = cancel or asyncio.Event()
        self.progress = progress
        self.operation_id = str(uuid.uuid4())
        self.events: list[dict[str, Any]] = []
        self.state = State.IDLE
        self.started = time.monotonic()
        self.device_hash: str | None = None

    def check_cancelled(self) -> None:
        if self.cancel.is_set():
            raise PairingFailure("CANCELLED", State.VERIFICATION_FAILED,
                                 "operation cancelled; trust records unchanged")

    def transition(self, state: State, *, result: str = "progress",
                   error_class: str | None = None) -> None:
        before = self.state
        self.state = state
        event = {"timestamp": time.time(), "operation_id": self.operation_id,
                 "state_before": before.value, "state_after": state.value,
                 "backend": type(self.backend).__name__,
                 "duration_ms": round((time.monotonic() - self.started) * 1000),
                 "result": result, "error_class": error_class}
        if self.device_hash:
            event["hashed_device_identifier"] = self.device_hash
        self.events.append(event)
        logs = self.support / "logs"
        logs.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(logs, 0o700)
        log_path = logs / "pairing-events.jsonl"
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(log_path, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            os.write(descriptor,
                     (json.dumps(event, separators=(",", ":")) + "\n").encode())
        finally:
            os.close(descriptor)
        if self.progress:
            self.progress({"operation": "pair_verify", "status": "progress",
                           "operationId": self.operation_id,
                           "protocolVersion": PROTOCOL_VERSION,
                           "bridgeVersion": BRIDGE_VERSION,
                           "state": state.value, "events": list(self.events)})

    def receipt_path(self, udid: str) -> Path:
        digest = hashlib.sha256(udid.encode()).hexdigest()[:24]
        return self.support / "trusted-devices" / f"{digest}.json"

    def read_receipt(self, udid: str) -> dict[str, Any] | None:
        path = self.receipt_path(udid)
        try:
            if path.is_symlink():
                return None
            value = json.loads(path.read_text())
            return value if value.get("device", {}).get("udid") == udid else None
        except (OSError, json.JSONDecodeError):
            return None

    def persist(self, udid: str, value: dict[str, Any]) -> None:
        path = self.receipt_path(udid)
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(path.parent, 0o700)
        temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
        encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            os.close(descriptor)
            try: temporary.unlink()
            except FileNotFoundError: pass

    async def _trusted(self, udid: str, pair: bool, remaining: float):
        try:
            return await asyncio.wait_for(
                self.backend.open_trusted_session(udid, pair=pair, timeout=remaining),
                timeout=max(1, remaining + 5))
        except PairingFailure:
            raise
        except Exception as error:
            name = type(error).__name__
            if name == "UserDeniedPairingError":
                raise PairingFailure("TRUST_DENIED", State.TRUST_DENIED, str(error)) from error
            # Lockdown's Pair request reports a locked device as
            # PasswordRequiredError (the response error is
            # "PasswordProtected").  Other Apple services use the two
            # passcode-named exceptions.  All three are user-remediable wait
            # states and must resume automatically after unlock rather than
            # being collapsed into a terminal Lockdown failure.
            if name in {"PasswordRequiredError", "PasscodeRequiredError",
                        "DeviceHasPasscodeSetError"}:
                raise PairingFailure("DEVICE_LOCKED", State.DEVICE_LOCKED, str(error)) from error
            if name == "PairingDialogResponsePendingError":
                raise PairingFailure("TRUST_REQUIRED", State.TRUST_REQUIRED, str(error)) from error
            if isinstance(error, (TimeoutError, asyncio.TimeoutError)):
                raise PairingFailure("TIMEOUT", State.TRUST_REQUIRED, str(error)) from error
            raise PairingFailure("LOCKDOWN_VALIDATION_FAILED", State.LOCKDOWN_FAILED,
                                 f"{name}: {error}") from error

    async def run(self, target: str | None = None, *, allow_pair: bool = False,
                  expected_protocol: int = PROTOCOL_VERSION,
                  allow_host_enrollment: bool = False) -> dict[str, Any]:
        try:
            if expected_protocol != PROTOCOL_VERSION:
                raise PairingFailure("PROTOCOL_VERSION_MISMATCH",
                                     State.PROTOCOL_VERSION_MISMATCH,
                                     f"expected {expected_protocol}, bridge {PROTOCOL_VERSION}")
            self.transition(State.DISCOVERING_MAC)
            self.check_cancelled()
            _, fingerprint = MacIdentity(self.support).ensure()
            self.transition(State.MAC_FOUND)
            self.transition(State.WAITING_FOR_USB)
            try:
                devices = await asyncio.wait_for(
                    self.backend.list_devices(), timeout=max(.1, min(15, self.timeout)))
            except (TimeoutError, asyncio.TimeoutError) as error:
                raise PairingFailure("TIMEOUT", State.TRANSPORT_FAILED,
                                     "USB discovery exceeded its bounded timeout") from error
            except Exception as error:
                raise PairingFailure("BACKEND_UNAVAILABLE", State.BACKEND_UNAVAILABLE,
                                     f"USB discovery failed: {type(error).__name__}") from error
            self.check_cancelled()
            if target:
                matches = [d for d in devices if d.udid == target]
                if not matches:
                    raise PairingFailure("USB_NOT_CONNECTED", State.NO_USB_DEVICE,
                                         "selected UDID is not connected by USB")
                selected = matches[0]
            elif len(devices) == 1:
                selected = devices[0]
            elif not devices:
                raise PairingFailure("USB_NOT_CONNECTED", State.NO_USB_DEVICE,
                                     "no USB Apple device is connected")
            else:
                # Selection candidates cross the backend/UI boundary and are
                # also preserved as evidence.  Never place raw UDIDs in the
                # diagnostic or pairing event log.  The UI receives a stable
                # per-observation opaque hash plus non-secret display data;
                # the exact UDID is supplied only after the operator selects
                # the corresponding device through the Mac-side picker.
                candidates = [{
                    "deviceHash": hashlib.sha256(device.udid.encode()).hexdigest()[:16],
                    "deviceName": device.name,
                    "productType": device.product_type,
                    "productVersion": device.product_version,
                    "buildVersion": device.build_version,
                    "connectionType": device.connection_type,
                } for device in devices]
                raise PairingFailure("MULTIPLE_DEVICES", State.MULTIPLE_DEVICES,
                                     f"{len(devices)} USB Apple devices require explicit selection",
                                     {"candidates": candidates})
            device_hash = hashlib.sha256(selected.udid.encode()).hexdigest()[:16]
            self.device_hash = device_hash
            self.events[-1]["hashed_device_identifier"] = device_hash
            self.transition(State.DEVICE_DISCOVERED)
            self.transition(State.CHECKING_PAIRING)
            receipt = self.read_receipt(selected.udid)
            client = None
            info = None
            try:
                client, info = await self._trusted(selected.udid, False, min(10, self.timeout))
                self.transition(State.ALREADY_PAIRED)
            except PairingFailure as first:
                # A locked device is not evidence that an Apple pair record is
                # stale.  Wait for unlock and retry the existing authenticated
                # session *without* autopair first.  This also handles an
                # already Apple-paired device being enrolled with 0-Sky for the
                # first time: unlocking must not cause an unnecessary new
                # pairing request or Trust prompt.
                if first.code == "DEVICE_LOCKED":
                    deadline = time.monotonic() + self.timeout
                    while True:
                        self.transition(State.DEVICE_LOCKED,
                                        error_class="DEVICE_LOCKED")
                        self.check_cancelled()
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise PairingFailure("TIMEOUT", State.DEVICE_LOCKED,
                                                 "device remained locked")
                        await asyncio.sleep(min(self.poll_interval, max(0, remaining)))
                        self.check_cancelled()
                        try:
                            client, info = await self._trusted(
                                selected.udid, False, min(5, remaining))
                            self.transition(State.ALREADY_PAIRED)
                            break
                        except PairingFailure as retry:
                            if retry.code in ("DEVICE_LOCKED", "TIMEOUT"):
                                continue
                            first = retry
                            break
                if client is None:
                    if receipt:
                        self.transition(State.PAIR_RECORD_STALE, result="stale",
                                        error_class=first.code)
                    if not allow_pair:
                        raise PairingFailure(
                            "PAIR_RECORD_STALE" if receipt else "TRUST_REQUIRED",
                            State.PAIR_RECORD_STALE if receipt else State.TRUST_REQUIRED,
                            first.diagnostic) from first
                    self.transition(State.PAIRING_REQUIRED)
                    self.transition(State.REQUESTING_PAIR)
                    self.transition(State.WAITING_FOR_TRUST)
                    deadline = time.monotonic() + self.timeout
                    while True:
                        self.check_cancelled()
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise PairingFailure("TIMEOUT", State.TRUST_REQUIRED,
                                                 "Apple Trust approval timed out")
                        try:
                            # Use short bounded attempts so Cancel and device
                            # detach are observed while Apple waits for a human
                            # Trust/passcode decision. The overall deadline stays
                            # user-oriented and much longer.
                            client, info = await self._trusted(
                                selected.udid, True, min(5, remaining))
                            break
                        except PairingFailure as pending:
                            if pending.code in ("DEVICE_LOCKED", "TRUST_REQUIRED", "TIMEOUT"):
                                if pending.code == "DEVICE_LOCKED":
                                    self.transition(State.DEVICE_LOCKED, error_class=pending.code)
                                else:
                                    # Apple's consent remains user-controlled. A
                                    # pending dialog is a user-driven wait state,
                                    # not a failed pairing attempt.
                                    self.transition(State.TRUST_REQUIRED,
                                                    error_class=pending.code)
                                await asyncio.sleep(min(self.poll_interval, max(0, remaining)))
                                self.transition(State.WAITING_FOR_TRUST)
                                continue
                            raise
            try:
                self.transition(State.VALIDATING_LOCKDOWN)
                self.transition(State.VERIFYING_DEVICE_IDENTITY)
                answered = str(info.get("UniqueDeviceID") or getattr(client, "udid", ""))
                if answered != selected.udid:
                    answered_hash = hashlib.sha256(answered.encode()).hexdigest()[:16]
                    raise PairingFailure("DEVICE_IDENTITY_MISMATCH",
                                         State.DEVICE_IDENTITY_MISMATCH,
                                         f"selectedHash={device_hash}, answeredHash={answered_hash}")
                self.transition(State.VERIFYING_HOST_IDENTITY)
                self.check_cancelled()
                if not receipt and not allow_host_enrollment:
                    raise PairingFailure("HOST_ENROLLMENT_REQUIRED",
                                         State.HOST_CONFIRMATION_REQUIRED,
                                         "live Apple session exists but 0-Sky host enrollment was not confirmed")
                if receipt and receipt.get("host", {}).get("publicKeyFingerprint") != fingerprint:
                    raise PairingFailure("HOST_IDENTITY_MISMATCH", State.HOST_IDENTITY_MISMATCH,
                                         "saved Mac public-key fingerprint changed")
                self.transition(State.VERIFYING_SERVICES)
                self.check_cancelled()
                remote_services = {"status": "NOT_REQUIRED", "provider": None}
                verifier = getattr(self.backend, "verify_remote_services", None)
                if verifier:
                    try:
                        remote_services = await asyncio.wait_for(
                            verifier(selected.udid, min(15, self.timeout)),
                            timeout=min(20, self.timeout + 5))
                    except Exception as error:
                        remote_services = {"status": "FAIL",
                                           "provider": type(self.backend).__name__,
                                           "errorClass": type(error).__name__}
                self.transition(State.CLASSIFYING_DEVICE)
                self.check_cancelled()
                product = str(info.get("ProductType", selected.product_type))
                platform_class = "IPAD" if product.startswith("iPad") else (
                    "IPHONE" if product.startswith("iPhone") else "UNKNOWN")
                research = "UNKNOWN"  # evaluated later by the independent SRD guard
                now = int(time.time())
                result = {
                    "operation": "pair_verify", "status": "verified",
                    "protocolVersion": PROTOCOL_VERSION, "bridgeVersion": BRIDGE_VERSION,
                    "operationId": self.operation_id,
                    "device": {"udid": selected.udid,
                        "deviceName": info.get("DeviceName", selected.name),
                        "productType": product,
                        "productVersion": str(info.get("ProductVersion", selected.product_version)),
                        "buildVersion": str(info.get("BuildVersion", selected.build_version)),
                        "serialNumber": info.get("SerialNumber"),
                        "platform": platform_class},
                    "pairing": {"applePairingEstablished": True,
                        "lockdownSessionValidated": True,
                        "expectedUDIDMatched": True,
                        "transportValidated": True,
                        "lastVerifiedAt": now},
                    "host": {"identityVerified": True,
                        "publicKeyFingerprint": fingerprint,
                        "name": socket.gethostname(), "os": platform.platform()},
                    "transport": {"usb": True,
                        "remoteServices": remote_services},
                    "capabilities": {
                        "platform": platform_class,
                        "supportsWifiLockdown": platform_class in ("IPHONE", "IPAD"),
                        "remoteServiceStatus": remote_services.get("status"),
                        "requiresIndependentSRDGuard": True},
                    "researchClass": research,
                    "events": self.events,
                }
                self.check_cancelled()
                self.persist(selected.udid, result)
                self.transition(State.VERIFIED_TRUSTED, result="verified")
                result["events"] = self.events
                return result
            finally:
                close = getattr(client, "close", None)
                if close:
                    value = close()
                    if asyncio.iscoroutine(value): await value
        except PairingFailure as error:
            self.transition(error.state, result="failed", error_class=error.code)
            message, remediation = ERRORS.get(error.code, ("Pairing verification failed.", "Review Advanced Diagnostics."))
            result = {"operation": "pair_verify", "status": "failed",
                    "protocolVersion": PROTOCOL_VERSION, "bridgeVersion": BRIDGE_VERSION,
                    "operationId": self.operation_id, "errorCode": error.code,
                    "userMessage": message, "safeRemediation": remediation,
                    "developerDiagnostic": error.diagnostic, "events": self.events}
            result.update(error.details)
            return result
        except Exception as error:
            self.transition(State.VERIFICATION_FAILED, result="failed",
                            error_class="BACKEND_UNAVAILABLE")
            message, remediation = ERRORS["BACKEND_UNAVAILABLE"]
            return {"operation": "pair_verify", "status": "failed",
                    "protocolVersion": PROTOCOL_VERSION, "bridgeVersion": BRIDGE_VERSION,
                    "operationId": self.operation_id,
                    "errorCode": "BACKEND_UNAVAILABLE", "userMessage": message,
                    "safeRemediation": remediation,
                    "developerDiagnostic": type(error).__name__, "events": self.events}


async def async_main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--support", type=Path,
                        default=Path.home() / "Library/Application Support/0-Sky")
    parser.add_argument("--target", help="exact UDID; omit only when one USB device exists")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify-only", action="store_true")
    mode.add_argument(
        "--confirm-host-enrollment", action="store_true",
        help="explicitly authorize Apple pairing and first-time 0-Sky host enrollment",
    )
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--protocol-version", type=int, default=PROTOCOL_VERSION)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = await MacPairingCoordinator(args.support, timeout=args.timeout).run(
        args.target, allow_pair=args.confirm_host_enrollment,
        allow_host_enrollment=args.confirm_host_enrollment,
        expected_protocol=args.protocol_version)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True); args.output.write_text(text)
    print(text, end="")
    return 0 if result["status"] == "verified" else 2


def main() -> int:
    return asyncio.run(async_main())


if __name__ == "__main__":
    raise SystemExit(main())
