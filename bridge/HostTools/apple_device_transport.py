#!/usr/bin/env python3
"""Transport selection and wireless provisioning for an already trusted device.

This module never creates or exports Apple pair records.  It references the
pairing maintained by Apple's stack/pymobiledevice3 and treats trust,
reachability, transport, and authenticated-session state as separate facts.
"""

from __future__ import annotations

import asyncio
import argparse
import dataclasses
import enum
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid
from typing import Any, Protocol


WIRELESS_PROTOCOL_VERSION = 1


class TransportType(str, enum.Enum):
    USB_LOCKDOWN = "USB_LOCKDOWN"
    WIFI_LOCKDOWN = "WIFI_LOCKDOWN"
    NATIVE_REMOTEXPC = "NATIVE_REMOTEXPC"
    USERSPACE_RSD = "USERSPACE_RSD"
    LEGACY_TUNNEL = "LEGACY_TUNNEL"
    NONE = "NONE"
    # Source compatibility for older callers.  New serialized state always
    # uses the explicit transport names above.
    USB = "USB_LOCKDOWN"
    UNAVAILABLE = "NONE"


class TrustState(str, enum.Enum):
    UNKNOWN = "UNKNOWN"
    TRUSTED = "TRUSTED"
    INVALID = "INVALID"


class TransportState(str, enum.Enum):
    NONE = "NONE"
    USB = "USB"
    WIFI = "WIFI"
    USB_AND_WIFI = "USB_AND_WIFI"


class SessionState(str, enum.Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    VERIFIED = "VERIFIED"
    DEGRADED = "DEGRADED"


class ConnectionState(str, enum.Enum):
    DISCONNECTED = "DISCONNECTED"
    DISCOVERING = "DISCOVERING"
    DEVICE_FOUND = "DEVICE_FOUND"
    VERIFYING_IDENTITY = "VERIFYING_IDENTITY"
    AUTHENTICATING_HOST = "AUTHENTICATING_HOST"
    SELECTING_TRANSPORT = "SELECTING_TRANSPORT"
    CONNECTING = "CONNECTING"
    VERIFYING_SESSION = "VERIFYING_SESSION"
    CONNECTED = "CONNECTED"
    WIRELESS_NOT_CONFIGURED = "WIRELESS_NOT_CONFIGURED"
    WIRELESS_ENABLING = "WIRELESS_ENABLING"
    WIRELESS_DISCOVERING = "WIRELESS_DISCOVERING"
    WIRELESS_WAITING_FOR_DISCONNECT = "WIRELESS_WAITING_FOR_DISCONNECT"
    WIRELESS_CONNECTING = "WIRELESS_CONNECTING"
    WIRELESS_VERIFYING = "WIRELESS_VERIFYING"
    WIRELESS_READY = "WIRELESS_READY"
    WIRELESS_FAILED = "WIRELESS_FAILED"
    OFFLINE = "OFFLINE"


@dataclasses.dataclass(frozen=True)
class WirelessCapabilities:
    supportsWifiLockdown: bool
    supportsRemotePairing: bool
    supportsNativeRemoteXPC: bool
    supportsUserspaceRSD: bool
    requiresUSBForFeature: tuple[str, ...] = ()


@dataclasses.dataclass
class TrustedDeviceRelationship:
    """One non-secret trust relationship with independent transport state.

    Apple's pairing and RemotePairing records remain in their legitimate
    backend stores.  This model records only verified facts and capabilities.
    """

    deviceIdentifier: str
    productType: str = ""
    deviceName: str = ""
    platform: str = "UNKNOWN"
    trustedMacFingerprint: str = ""
    applePairingValid: bool = False
    lockdownValidated: bool = False
    wifiLockdownEnabled: bool = False
    # Durable capability proof.  ``wifiAvailable`` is only a live reachability
    # observation and may legitimately become false after reconnecting USB or
    # leaving the network; it must not erase a completed fallback verification.
    wifiPairingVerified: bool = False
    remotePairingReady: bool = False
    wirelessRSDVerified: bool = False
    usbAvailable: bool = False
    wifiAvailable: bool = False
    lastVerifiedTransport: str = TransportType.NONE.value
    lastVerifiedAt: int = 0
    trustState: str = TrustState.UNKNOWN.value
    transportState: str = TransportState.NONE.value
    sessionState: str = SessionState.DISCONNECTED.value

    def as_record(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_record(cls, value: dict[str, Any]) -> "TrustedDeviceRelationship":
        # Migrate the original capability-record schema without copying or
        # interpreting any Apple pairing material.
        wifi_enabled = bool(value.get("wifiLockdownEnabled",
                                      value.get("wirelessEnabled", False)))
        last_transport = str(value.get("lastVerifiedTransport") or
                             value.get("lastTransport") or TransportType.NONE.value)
        wifi_verified = value.get("wifiPairingVerified")
        if wifi_verified is None:
            wifi_verified = bool(value.get("wirelessVerified") or
                (wifi_enabled and (value.get("wifiAvailable") or last_transport in (
                    TransportType.WIFI_LOCKDOWN.value,
                    TransportType.NATIVE_REMOTEXPC.value,
                    TransportType.USERSPACE_RSD.value))))
        return cls(
            deviceIdentifier=str(value.get("deviceIdentifier") or value.get("deviceID") or ""),
            productType=str(value.get("productType") or ""),
            deviceName=str(value.get("deviceName") or ""),
            platform=str(value.get("platform") or "UNKNOWN"),
            trustedMacFingerprint=str(value.get("trustedMacFingerprint") or
                                         value.get("hostFingerprint") or ""),
            applePairingValid=bool(value.get("applePairingValid", True)),
            lockdownValidated=bool(value.get("lockdownValidated", True)),
            wifiLockdownEnabled=wifi_enabled,
            wifiPairingVerified=bool(wifi_verified),
            remotePairingReady=bool(value.get("remotePairingReady", False)),
            wirelessRSDVerified=bool(value.get("wirelessRSDVerified", False)),
            usbAvailable=bool(value.get("usbAvailable", False)),
            wifiAvailable=bool(value.get("wifiAvailable",
                                          value.get("wirelessVerified", False))),
            lastVerifiedTransport=last_transport,
            lastVerifiedAt=int(value.get("lastVerifiedAt") or
                               value.get("lastVerified") or 0),
            trustState=str(value.get("trustState") or TrustState.TRUSTED.value),
            transportState=str(value.get("transportState") or TransportState.NONE.value),
            sessionState=str(value.get("sessionState") or SessionState.DISCONNECTED.value),
        )


class TransportBackend(Protocol):
    async def discover(self) -> list[dict[str, Any]]: ...
    async def open_lockdown(self, udid: str, transport: TransportType) -> tuple[Any, dict[str, Any]]: ...
    async def set_wifi_lockdown(self, client: Any, enabled: bool) -> None: ...
    async def get_wifi_lockdown(self, client: Any) -> bool: ...
    async def prepare_remote_pairing(self, client: Any) -> dict[str, Any]: ...
    async def native_remote_services(self, udid: str, timeout: float) -> list[Any]: ...


class PymobiledeviceTransportBackend:
    """Structured pymobiledevice3 backend; no human CLI parsing."""

    @staticmethod
    async def _call(function, *args, **kwargs):
        # pymobiledevice3's usbmux/Lockdown APIs are native coroutines in
        # current releases.  Await them directly so cancellation cannot strand
        # a coroutine object created inside a worker thread.  Keep to_thread
        # only for synchronous compatibility backends.
        if inspect.iscoroutinefunction(function):
            return await function(*args, **kwargs)
        value = await asyncio.to_thread(function, *args, **kwargs)
        return await value if inspect.isawaitable(value) else value

    async def discover(self) -> list[dict[str, Any]]:
        from pymobiledevice3.usbmux import list_devices
        values = await self._call(list_devices)
        return [{"udid": str(item.serial),
                 "connectionType": str(getattr(item, "connection_type", "UNKNOWN"))}
                for item in values]

    async def open_lockdown(self, udid: str, transport: TransportType) -> tuple[Any, dict[str, Any]]:
        from pymobiledevice3.lockdown import create_using_usbmux
        connection = "USB" if transport is TransportType.USB else "Network"
        # autopair=False is essential: a transport change must never silently
        # alter the established Apple trust relationship.
        client = await self._call(
            create_using_usbmux, serial=udid, connection_type=connection,
            autopair=False, label="0-Sky Mac Bridge")
        # create_using_usbmux() has already validated and started the
        # Lockdown session. Repeating validate_pairing() on that connection
        # produces SessionActive on physical iPhone/iPad hardware.
        paired = getattr(client, "paired", None)
        valid = (await self._call(client.validate_pairing)
                 if paired is None else bool(paired))
        if not valid:
            await self.close(client)
            raise RuntimeError("LOCKDOWN_VALIDATION_FAILED")
        values = await self._call(client.get_value)
        return client, values

    async def set_wifi_lockdown(self, client: Any, enabled: bool) -> None:
        # pymobiledevice3 exposes this setting as a Python property, not as
        # set_enable_wifi_connections()/get_enable_wifi_connections() methods.
        # Assigning an unknown attribute on a compatibility client can create
        # shadow state, so call Lockdown's structured SetValue API directly.
        # This also makes the exact domain/key visible to review and tests.
        setter = getattr(client, "set_value", None)
        if not callable(setter):
            raise RuntimeError("WIRELESS_BACKEND_UNSUPPORTED")
        await self._call(
            setter,
            bool(enabled),
            "com.apple.mobile.wireless_lockdown",
            "EnableWifiConnections",
        )

    async def get_wifi_lockdown(self, client: Any) -> bool:
        getter = getattr(client, "get_value", None)
        if not callable(getter):
            raise RuntimeError("WIRELESS_BACKEND_UNSUPPORTED")
        return bool(await self._call(
            getter,
            "com.apple.mobile.wireless_lockdown",
            "EnableWifiConnections",
        ))

    async def prepare_remote_pairing(self, client: Any) -> dict[str, Any]:
        """Pair/verify RemotePairing through an authenticated USB Lockdown session."""
        from pymobiledevice3.exceptions import RemotePairingCompletedError
        from pymobiledevice3.remote.tunnel_service import RemotePairingLockdownService

        expected = str(getattr(client, "udid", ""))
        if not expected:
            raise RuntimeError("DEVICE_IDENTITY_MISMATCH")
        service = await RemotePairingLockdownService.create(client)
        try:
            try:
                await service.connect(autopair=True)
            except RemotePairingCompletedError:
                # Pair-setup deliberately closes the control channel.  Reopen
                # it and require pair-verify before reporting readiness.
                await service.close()
                service = await RemotePairingLockdownService.create(client)
                await service.connect(autopair=False)
            if str(service.remote_identifier) != expected:
                raise RuntimeError("DEVICE_IDENTITY_MISMATCH")
            info = service.handshake_info or {}
            options = info.get("deviceOptions") if isinstance(info, dict) else {}
            return {
                "verified": True,
                "wireProtocolVersion": info.get("wireProtocolVersion"),
                "allowsIncomingTunnelConnections": bool(
                    isinstance(options, dict) and
                    options.get("allowsIncomingTunnelConnections")),
            }
        finally:
            await service.close()

    async def native_remote_services(self, udid: str, timeout: float) -> list[Any]:
        from pymobiledevice3.remote.tunnel_service import (
            get_core_device_tunnel_services, get_remote_pairing_tunnel_services)
        services = await get_core_device_tunnel_services(bonjour_timeout=timeout, udid=udid)
        if not services:
            services = await get_remote_pairing_tunnel_services(bonjour_timeout=timeout, udid=udid)
        return services

    async def native_coredevice(self, udid: str, timeout: float = 15) -> dict[str, Any] | None:
        """Ask Apple's unprivileged CoreDevice stack for an authenticated path."""
        environment = dict(os.environ)
        # xcrun honors the selected Xcode and an explicit DEVELOPER_DIR.
        command = ["/usr/bin/xcrun", "devicectl"]
        with tempfile.TemporaryDirectory(prefix="0sky-coredevice-") as directory:
            output = Path(directory) / "device.json"
            completed = await asyncio.to_thread(
                subprocess.run,
                [*command, "device", "info", "details",
                 "--device", udid, "--json-output", str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                check=False, env=environment)
            if completed.returncode or not output.is_file():
                return None
            value = json.loads(output.read_text())
            device = value.get("result", {}).get("device") or value.get("result", {})
            properties = device.get("properties", {})
            connection = properties.get("connection", device.get("connectionProperties", {}))
            hardware = properties.get("hardware", device.get("hardwareProperties", {}))
            software = properties.get("software", device.get("deviceProperties", {}))
            answered = str(hardware.get("udid", ""))
            if answered != udid:
                raise RuntimeError("DEVICE_IDENTITY_MISMATCH")
            if str(connection.get("pairingState", "")).lower() != "paired":
                raise RuntimeError("LOCKDOWN_VALIDATION_FAILED")
            transport = str(connection.get("transportType", ""))
            # Current devicectl schemas expose the live CoreDevice path as
            # ``tunnelState``. Older releases used ``state``/``deviceState``.
            state = str(connection.get(
                "tunnelState", connection.get("state", connection.get("deviceState", ""))))
            return {"udid": answered, "transportType": transport,
                    "state": state, "pairingState": connection.get("pairingState"),
                    "productType": hardware.get("productType"),
                    "productVersion": (software.get("osVersionNumber", {}).get("stringValue")
                        if isinstance(software.get("osVersionNumber"), dict)
                        else software.get("osVersionNumber")),
                    "buildVersion": (software.get("osBuildVersions", {}).get("buildVersion", {}).get("name")
                        if isinstance(software.get("osBuildVersions"), dict)
                        else software.get("osBuildUpdate"))}

    async def close(self, value: Any) -> None:
        close = getattr(value, "close", None)
        if close:
            result = close()
            if asyncio.iscoroutine(result):
                await result


class WirelessCapabilityDetector:
    def detect(self, product_type: str, product_version: str) -> WirelessCapabilities:
        try:
            major = int(str(product_version).split(".", 1)[0])
        except ValueError:
            major = 0
        apple_mobile = product_type.startswith(("iPhone", "iPad"))
        return WirelessCapabilities(
            supportsWifiLockdown=apple_mobile,
            supportsRemotePairing=apple_mobile and major >= 17,
            supportsNativeRemoteXPC=apple_mobile and major >= 17,
            supportsUserspaceRSD=apple_mobile and major >= 17,
            requiresUSBForFeature=("INITIAL_APPLE_TRUST", "TRUST_REPAIR"),
        )


class TrustedDeviceRegistry:
    """Non-secret capability registry. Apple pairing material stays external."""

    def __init__(self, support: Path):
        self.root = support / "trusted-device-capabilities"

    def path(self, udid: str) -> Path:
        return self.root / (hashlib.sha256(udid.encode()).hexdigest()[:24] + ".json")

    def save(self, udid: str, value: dict[str, Any]) -> None:
        path = self.path(udid)
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

    def load(self, udid: str) -> dict[str, Any] | None:
        try:
            path = self.path(udid)
            if path.is_symlink():
                return None
            value = json.loads(path.read_text())
            answered = value.get("deviceIdentifier") or value.get("deviceID")
            return value if answered == udid else None
        except (OSError, json.JSONDecodeError):
            return None

    def load_relationship(self, udid: str) -> TrustedDeviceRelationship | None:
        value = self.load(udid)
        if value is None:
            return None
        relationship = TrustedDeviceRelationship.from_record(value)
        return relationship if relationship.deviceIdentifier == udid else None

    def save_relationship(self, relationship: TrustedDeviceRelationship) -> None:
        self.save(relationship.deviceIdentifier, relationship.as_record())


class AppleDeviceTransportManager:
    def __init__(self, support: Path, backend: TransportBackend | None = None):
        self.support = support.expanduser().resolve()
        self.backend = backend or PymobiledeviceTransportBackend()
        self.registry = TrustedDeviceRegistry(self.support)
        self.detector = WirelessCapabilityDetector()
        self.state = ConnectionState.DISCONNECTED
        self.events: list[dict[str, Any]] = []
        self._active_device_hash: str | None = None

    @staticmethod
    def _device_hash(udid: str) -> str:
        return hashlib.sha256(udid.encode("utf-8")).hexdigest()[:16]

    @classmethod
    def _safe_value(cls, value: Any) -> Any:
        """Keep logs useful without serializing identifiers or credentials."""
        if isinstance(value, dict):
            safe: dict[str, Any] = {}
            for key, item in value.items():
                lowered = str(key).lower()
                if any(secret in lowered for secret in (
                    "escrowbag", "privatekey", "pairrecord", "password", "token"
                )):
                    safe[str(key)] = "<redacted>"
                else:
                    safe[str(key)] = cls._safe_value(item)
            return safe
        if isinstance(value, (list, tuple)):
            return [cls._safe_value(item) for item in value]
        if isinstance(value, str):
            if "-----BEGIN " in value and "PRIVATE KEY-----" in value:
                return "<redacted-private-key>"

            def replace_identifier(match: re.Match[str]) -> str:
                return "<device:" + cls._device_hash(match.group(0)) + ">"

            return re.sub(
                r"(?i)(?<![0-9a-f])(?:[0-9a-f]{8}-[0-9a-f]{16}|[0-9a-f]{40})(?![0-9a-f])",
                replace_identifier,
                value,
            )
        return value

    @staticmethod
    def _error_code(error: BaseException) -> str:
        if isinstance(error, (asyncio.TimeoutError, TimeoutError, subprocess.TimeoutExpired)):
            return "TIMEOUT"
        text = str(error).strip()
        if re.fullmatch(r"[A-Z][A-Z0-9_]{2,79}", text):
            return text
        return "BACKEND_UNAVAILABLE"

    def transition(self, state: ConnectionState, **fields: Any) -> None:
        before = self.state; self.state = state
        event = {"timestamp": time.time(), "stateBefore": before.value,
                 "stateAfter": state.value, **self._safe_value(fields)}
        if self._active_device_hash:
            event["hashed_device_identifier"] = self._active_device_hash
        self.events.append(event)
        logs = self.support / "logs"
        logs.mkdir(parents=True, mode=0o700, exist_ok=True)
        os.chmod(logs, 0o700)
        log_path = logs / "transport-events.jsonl"
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

    @staticmethod
    def _same_device(expected: str, client: Any, info: dict[str, Any]) -> bool:
        return str(info.get("UniqueDeviceID") or getattr(client, "udid", "")) == expected

    async def discover(self) -> list[dict[str, Any]]:
        self.transition(ConnectionState.DISCOVERING)
        result = await self.backend.discover()
        if result: self.transition(ConnectionState.DEVICE_FOUND)
        else: self.transition(ConnectionState.OFFLINE)
        return result

    async def discover_usb(self, udid: str | None = None) -> list[dict[str, Any]]:
        values = await self.discover()
        return [item for item in values if
                (udid is None or item.get("udid") == udid) and
                str(item.get("connectionType", "")).upper() == "USB"]

    async def discover_wifi(self, udid: str | None = None) -> list[dict[str, Any]]:
        values = await self.discover()
        return [item for item in values if
                (udid is None or item.get("udid") == udid) and
                str(item.get("connectionType", "")).upper() in ("NETWORK", "WIFI")]

    def get_capabilities(self, product_type: str,
                         product_version: str) -> WirelessCapabilities:
        return self.detector.detect(product_type, product_version)

    @staticmethod
    def _transport_state(usb: bool, wifi: bool) -> str:
        if usb and wifi:
            return TransportState.USB_AND_WIFI.value
        if usb:
            return TransportState.USB.value
        if wifi:
            return TransportState.WIFI.value
        return TransportState.NONE.value

    def select_best_transport(self, *, usb_available: bool, wifi_available: bool,
                              requiring: str = "lockdown") -> list[TransportType]:
        """Return capability-aware candidates with USB first for normal work."""
        requirement = requiring.lower().replace("_", "")
        if requirement in ("requiresusb", "usb"):
            return [TransportType.USB_LOCKDOWN] if usb_available else []
        if requirement in ("requiresrsd", "rsd"):
            # RSD/RemoteXPC is a service requirement rather than a preference
            # for Wi-Fi. Apple's native stack may satisfy it over wired or
            # localNetwork transports.
            return [TransportType.NATIVE_REMOTEXPC, TransportType.USERSPACE_RSD]
        candidates: list[TransportType] = []
        if usb_available:
            candidates.append(TransportType.USB_LOCKDOWN)
        # Native RemoteXPC is a Wi-Fi fallback for ordinary bridge traffic,
        # not a reason to bypass an attached, verified USB transport.
        candidates.append(TransportType.NATIVE_REMOTEXPC)
        if wifi_available:
            candidates.append(TransportType.WIFI_LOCKDOWN)
        return candidates

    async def connect_usb(self, udid: str, host_fingerprint: str) -> dict[str, Any]:
        return await self.connect(udid, requiring="requiresUSB",
                                  host_fingerprint=host_fingerprint)

    async def connect_wifi(self, udid: str, host_fingerprint: str) -> dict[str, Any]:
        return await self.connect(udid, requiring="supportsWireless",
                                  host_fingerprint=host_fingerprint,
                                  allow_usb=False)

    async def verify_usb(self, udid: str, host_fingerprint: str) -> dict[str, Any]:
        return await self.connect_usb(udid, host_fingerprint)

    async def verify_wifi(self, udid: str, host_fingerprint: str) -> dict[str, Any]:
        return await self.verify_wireless(udid, host_fingerprint,
                                          require_usb_absent=True)

    async def switch_transport(self, udid: str, host_fingerprint: str,
                               requiring: str = "lockdown") -> dict[str, Any]:
        return await self.connect(udid, requiring=requiring,
                                  host_fingerprint=host_fingerprint)

    async def disconnect(self) -> None:
        self.transition(ConnectionState.DISCONNECTED)

    async def connect(self, udid: str, *, requiring: str = "lockdown",
                      host_fingerprint: str | None = None,
                      allow_usb: bool = True) -> dict[str, Any]:
        """Use USB first for normal work and verified Wi-Fi as the fallback."""
        self._active_device_hash = self._device_hash(udid)
        self.transition(ConnectionState.SELECTING_TRANSPORT)
        relationship = self.registry.load_relationship(udid)
        host_verified = bool(relationship and host_fingerprint and
                             relationship.trustedMacFingerprint == host_fingerprint)
        discovered = await self.backend.discover()
        available = {str(x.get("connectionType", "")).upper(): x for x in discovered
                     if x.get("udid") == udid}
        usb_available = allow_usb and "USB" in available
        wifi_available = any(x in available for x in ("NETWORK", "WIFI"))
        candidates = self.select_best_transport(
            usb_available=usb_available, wifi_available=wifi_available,
            requiring=requiring)
        errors = []
        for transport in candidates:
            try:
                if transport in (TransportType.NATIVE_REMOTEXPC,
                                 TransportType.USERSPACE_RSD):
                    native = getattr(self.backend, "native_coredevice", None)
                    if not native or not host_verified:
                        raise RuntimeError("HOST_IDENTITY_MISMATCH")
                    core = await native(udid)
                    state = str((core or {}).get("state", "")).lower()
                    path = str((core or {}).get("transportType", "")).lower()
                    requirement = requiring.lower().replace("_", "")
                    acceptable = state == "connected" and (
                        path == "localnetwork" or requirement in ("requiresrsd", "rsd"))
                    if not core or not acceptable:
                        raise RuntimeError("WIRELESS_NOT_DISCOVERED")
                    relationship = relationship or TrustedDeviceRelationship(udid)
                    relationship.applePairingValid = True
                    relationship.lockdownValidated = True
                    relationship.wifiAvailable = path == "localnetwork"
                    if relationship.wifiAvailable:
                        relationship.wifiPairingVerified = True
                    relationship.usbAvailable = usb_available
                    relationship.wirelessRSDVerified = True
                    relationship.lastVerifiedTransport = transport.value
                    relationship.lastVerifiedAt = int(time.time())
                    relationship.trustState = TrustState.TRUSTED.value
                    relationship.transportState = self._transport_state(
                        usb_available, relationship.wifiAvailable)
                    relationship.sessionState = SessionState.VERIFIED.value
                    self.registry.save_relationship(relationship)
                    self.transition(ConnectionState.CONNECTED, transport=transport.value)
                    return {"status": "connected", "trusted": True,
                            "hostIdentityVerified": True,
                            "hostFingerprint": host_fingerprint,
                            "transport": transport.value, "session": "VERIFIED",
                            "trustState": relationship.trustState,
                            "transportState": relationship.transportState,
                            "device": core, "relationship": relationship.as_record(),
                            "events": self.events}
                self.transition(ConnectionState.CONNECTING, transport=transport.value)
                client, info = await self.backend.open_lockdown(udid, transport)
                try:
                    self.transition(ConnectionState.VERIFYING_IDENTITY, transport=transport.value)
                    if not self._same_device(udid, client, info):
                        raise RuntimeError("DEVICE_IDENTITY_MISMATCH")
                    self.transition(ConnectionState.VERIFYING_SESSION, transport=transport.value)
                    if not host_verified:
                        raise RuntimeError("HOST_IDENTITY_MISMATCH")
                    # Never emit CONNECTED until both the Apple session and
                    # the enrolled 0-Sky host identity are verified.
                    relationship = relationship or TrustedDeviceRelationship(udid)
                    relationship.productType = str(info.get("ProductType") or "")
                    relationship.deviceName = str(info.get("DeviceName") or "")
                    relationship.platform = ("IPAD" if relationship.productType.startswith("iPad")
                                             else "IPHONE")
                    relationship.trustedMacFingerprint = str(host_fingerprint)
                    relationship.applePairingValid = True
                    relationship.lockdownValidated = True
                    relationship.usbAvailable = usb_available
                    relationship.wifiAvailable = (transport is TransportType.WIFI_LOCKDOWN)
                    if transport is TransportType.WIFI_LOCKDOWN:
                        relationship.wifiLockdownEnabled = True
                        relationship.wifiPairingVerified = True
                    relationship.lastVerifiedTransport = transport.value
                    relationship.lastVerifiedAt = int(time.time())
                    relationship.trustState = TrustState.TRUSTED.value
                    relationship.transportState = self._transport_state(
                        relationship.usbAvailable, relationship.wifiAvailable)
                    relationship.sessionState = SessionState.VERIFIED.value
                    self.registry.save_relationship(relationship)
                    self.transition(ConnectionState.CONNECTED, transport=transport.value)
                    return {"status": "connected", "trusted": True,
                            "hostIdentityVerified": True,
                            "hostFingerprint": host_fingerprint,
                            "transport": transport.value, "session": "VERIFIED",
                            "trustState": relationship.trustState,
                            "transportState": relationship.transportState,
                            "device": {"udid": udid,
                                "productType": info.get("ProductType"),
                                "productVersion": info.get("ProductVersion"),
                                "buildVersion": info.get("BuildVersion")},
                            "relationship": relationship.as_record(),
                            "events": self.events}
                finally:
                    close = getattr(self.backend, "close", None)
                    if close: await close(client)
            except Exception as error:
                if transport in (TransportType.NATIVE_REMOTEXPC,
                                 TransportType.USERSPACE_RSD,
                                 TransportType.WIFI_LOCKDOWN):
                    self.transition(ConnectionState.WIRELESS_FAILED,
                                    transport=transport.value,
                                    errorCode=self._error_code(error))
                errors.append({"transport": transport.value,
                               "errorCode": self._error_code(error)})
        self.transition(ConnectionState.OFFLINE)
        if relationship and host_verified:
            relationship.usbAvailable = usb_available
            relationship.wifiAvailable = wifi_available
            relationship.transportState = self._transport_state(usb_available, wifi_available)
            relationship.sessionState = SessionState.DEGRADED.value
            self.registry.save_relationship(relationship)
        return {"status": "offline", "trusted": relationship is not None,
                "hostIdentityVerified": host_verified,
                "trustState": (relationship.trustState if relationship else TrustState.UNKNOWN.value),
                "transportState": (relationship.transportState if relationship else TransportState.NONE.value),
                "transport": TransportType.NONE.value, "errors": errors,
                "events": self.events}

    async def enable_wireless(self, udid: str, host_fingerprint: str,
                              *, usb_trust_verified: bool,
                              discovery_timeout: float = 20,
                              poll_interval: float = 1) -> dict[str, Any]:
        """Configure Wi-Fi and RemotePairing over verified USB.

        This phase cannot create a new Wi-Fi verification. Verification is a
        separate ``verify_wireless`` phase; an existing durable proof may be
        retained when the same Mac relationship is revalidated over USB.
        """
        self._active_device_hash = self._device_hash(udid)
        if not usb_trust_verified:
            return {"status": "failed", "errorCode": "USB_TRUST_REQUIRED",
                    "message": "Complete Apple's USB Trust ceremony first."}
        self.transition(ConnectionState.WIRELESS_ENABLING)
        client = None
        remote_pairing = {"verified": False, "required": False}
        try:
            client, info = await self.backend.open_lockdown(udid, TransportType.USB_LOCKDOWN)
            if not self._same_device(udid, client, info):
                raise RuntimeError("DEVICE_IDENTITY_MISMATCH")
            capabilities = self.detector.detect(str(info.get("ProductType", "")),
                                                str(info.get("ProductVersion", "")))
            if not capabilities.supportsWifiLockdown:
                raise RuntimeError("WIRELESS_UNSUPPORTED")
            await self.backend.set_wifi_lockdown(client, True)
            if not await self.backend.get_wifi_lockdown(client):
                raise RuntimeError("WIRELESS_READBACK_FAILED")
            remote_pairing["required"] = capabilities.supportsRemotePairing
            if capabilities.supportsRemotePairing:
                prepare = getattr(self.backend, "prepare_remote_pairing", None)
                if not prepare:
                    raise RuntimeError("REMOTE_PAIRING_BACKEND_UNSUPPORTED")
                remote_pairing = {"required": True, **await prepare(client)}
                if not remote_pairing.get("verified"):
                    raise RuntimeError("REMOTE_PAIRING_VERIFICATION_FAILED")
        except Exception as error:
            error_code = self._error_code(error)
            self.transition(ConnectionState.WIRELESS_FAILED, errorCode=error_code)
            return {"status": "failed", "errorCode": error_code,
                    "usbTrustPreserved": True, "events": self.events}
        finally:
            if client is not None:
                close = getattr(self.backend, "close", None)
                if close: await close(client)

        # Preserve a completed wireless proof across later USB verification.
        # Earlier releases conflated the live ``wifiAvailable`` observation
        # with the durable pairing result, so reconnecting USB reset the UI to
        # PENDING and forced an unnecessary second cable-removal ceremony.
        previous = self.registry.load_relationship(udid)
        previously_verified = bool(
            previous and previous.trustedMacFingerprint == host_fingerprint and
            previous.wifiLockdownEnabled and previous.wifiPairingVerified)

        # Record only non-secret capability state after USB trust, exact
        # identity, SET/readback, and required RemotePairing have succeeded.
        now = int(time.time())
        relationship = TrustedDeviceRelationship(
            deviceIdentifier=udid,
            productType=str(info.get("ProductType") or ""),
            deviceName=str(info.get("DeviceName") or ""),
            platform=("IPAD" if str(info.get("ProductType", "")).startswith("iPad") else "IPHONE"),
            trustedMacFingerprint=host_fingerprint,
            applePairingValid=True,
            lockdownValidated=True,
            wifiLockdownEnabled=True,
            wifiPairingVerified=previously_verified,
            remotePairingReady=bool(remote_pairing.get("verified") or
                                    not remote_pairing.get("required")),
            wirelessRSDVerified=False,
            usbAvailable=True,
            wifiAvailable=False,
            lastVerifiedTransport=(previous.lastVerifiedTransport if previously_verified
                                   else TransportType.USB_LOCKDOWN.value),
            lastVerifiedAt=(previous.lastVerifiedAt if previously_verified else now),
            trustState=TrustState.TRUSTED.value,
            transportState=TransportState.USB.value,
            sessionState=SessionState.VERIFIED.value,
        )
        self.registry.save_relationship(relationship)
        if previously_verified:
            self.transition(ConnectionState.WIRELESS_READY,
                            transport=relationship.lastVerifiedTransport)
            return {
                "status": "ready",
                "wifiLockdownEnabled": True,
                "wifiPairingVerified": True,
                "remotePairingReady": relationship.remotePairingReady,
                "wirelessRSDVerified": relationship.wirelessRSDVerified,
                "wirelessTrustedTransport": "READY",
                "requiresCableRemovalVerification": False,
                "verifiedTransport": relationship.lastVerifiedTransport,
                "relationship": relationship.as_record(),
                "capabilities": dataclasses.asdict(capabilities),
                "events": self.events,
            }
        self.transition(ConnectionState.WIRELESS_WAITING_FOR_DISCONNECT,
                        transport=TransportType.USB_LOCKDOWN.value)
        return {
            "status": "pending",
            "errorCode": "USB_DISCONNECT_REQUIRED",
            "wifiLockdownEnabled": True,
            "remotePairingReady": relationship.remotePairingReady,
            "wirelessRSDVerified": False,
            "usbTrustPreserved": True,
            "wirelessTrustedTransport": "PENDING",
            "requiresCableRemovalVerification": True,
            "relationship": relationship.as_record(),
            "capabilities": dataclasses.asdict(capabilities),
            "events": self.events,
        }

    async def verify_wireless(self, udid: str, host_fingerprint: str, *,
                              require_usb_absent: bool = True,
                              discovery_timeout: float = 30,
                              poll_interval: float = 1) -> dict[str, Any]:
        """Verify the configured relationship over network after USB removal."""
        self._active_device_hash = self._device_hash(udid)
        relationship = self.registry.load_relationship(udid)
        if not relationship or not relationship.wifiLockdownEnabled:
            return {"status": "failed", "errorCode": "WIRELESS_NOT_CONFIGURED",
                    "events": self.events}
        if relationship.trustedMacFingerprint != host_fingerprint:
            return {"status": "failed", "errorCode": "HOST_IDENTITY_MISMATCH",
                    "events": self.events}
        self.transition(ConnectionState.WIRELESS_DISCOVERING)
        deadline = time.monotonic() + discovery_timeout
        last_error = "WIRELESS_NOT_DISCOVERED"
        while time.monotonic() < deadline:
            found = await self.backend.discover()
            usb = any(item.get("udid") == udid and
                      str(item.get("connectionType", "")).upper() == "USB"
                      for item in found)
            network = any(item.get("udid") == udid and
                          str(item.get("connectionType", "")).upper() in ("NETWORK", "WIFI")
                          for item in found)
            if require_usb_absent and usb:
                relationship.usbAvailable = True
                relationship.transportState = self._transport_state(True, network)
                self.registry.save_relationship(relationship)
                self.transition(ConnectionState.WIRELESS_WAITING_FOR_DISCONNECT)
                return {"status": "pending", "errorCode": "USB_DISCONNECT_REQUIRED",
                        "wifiLockdownEnabled": True,
                        "remotePairingReady": relationship.remotePairingReady,
                        "requiresCableRemovalVerification": True,
                        "relationship": relationship.as_record(), "events": self.events}

            verified_transport: TransportType | None = None
            network_info: dict[str, Any] | None = None
            native = getattr(self.backend, "native_coredevice", None)
            if native:
                try:
                    core = await native(udid, min(5, max(.1, deadline - time.monotonic())))
                    if core and str(core.get("transportType", "")).lower() == "localnetwork" and \
                            str(core.get("state", "")).lower() == "connected":
                        if str(core.get("udid", udid)) != udid:
                            raise RuntimeError("DEVICE_IDENTITY_MISMATCH")
                        network_info = {
                            "UniqueDeviceID": udid,
                            "ProductType": core.get("productType") or relationship.productType,
                            "ProductVersion": core.get("productVersion"),
                            "BuildVersion": core.get("buildVersion"),
                            "DeviceName": relationship.deviceName,
                        }
                        verified_transport = TransportType.NATIVE_REMOTEXPC
                except Exception as error:
                    last_error = self._error_code(error)
            if verified_transport is None and network:
                wireless = None
                try:
                    self.transition(ConnectionState.WIRELESS_CONNECTING,
                                    transport=TransportType.WIFI_LOCKDOWN.value)
                    wireless, network_info = await self.backend.open_lockdown(
                        udid, TransportType.WIFI_LOCKDOWN)
                    if not self._same_device(udid, wireless, network_info):
                        raise RuntimeError("DEVICE_IDENTITY_MISMATCH")
                    verified_transport = TransportType.WIFI_LOCKDOWN
                except Exception as error:
                    last_error = self._error_code(error)
                finally:
                    if wireless is not None:
                        close = getattr(self.backend, "close", None)
                        if close: await close(wireless)
            if verified_transport is not None and network_info is not None:
                self.transition(ConnectionState.WIRELESS_VERIFYING,
                                transport=verified_transport.value)
                relationship.productType = str(network_info.get("ProductType") or
                                               relationship.productType)
                relationship.usbAvailable = usb
                relationship.wifiAvailable = True
                relationship.wifiPairingVerified = True
                relationship.wirelessRSDVerified = (
                    verified_transport is TransportType.NATIVE_REMOTEXPC)
                if relationship.wirelessRSDVerified:
                    relationship.remotePairingReady = True
                relationship.lastVerifiedTransport = verified_transport.value
                relationship.lastVerifiedAt = int(time.time())
                relationship.trustState = TrustState.TRUSTED.value
                relationship.transportState = self._transport_state(usb, True)
                relationship.sessionState = SessionState.VERIFIED.value
                self.registry.save_relationship(relationship)
                self.transition(ConnectionState.WIRELESS_READY,
                                transport=verified_transport.value)
                return {"status": "ready", "wirelessTrustedTransport": "READY",
                        "transport": verified_transport.value,
                        "verifiedTransport": verified_transport.value,
                        "wifiLockdownEnabled": True,
                        "remotePairingReady": relationship.remotePairingReady,
                        "wirelessRSDVerified": relationship.wirelessRSDVerified,
                        "device": relationship.as_record(),
                        "relationship": relationship.as_record(),
                        "events": self.events}
            await asyncio.sleep(poll_interval)
        relationship.usbAvailable = False
        relationship.wifiAvailable = False
        relationship.transportState = TransportState.NONE.value
        relationship.sessionState = SessionState.DEGRADED.value
        self.registry.save_relationship(relationship)
        self.transition(ConnectionState.WIRELESS_FAILED, errorCode=last_error)
        return {"status": "pending", "errorCode": last_error,
                "wifiLockdownEnabled": True,
                "remotePairingReady": relationship.remotePairingReady,
                "usbTrustPreserved": True, "wirelessTrustedTransport": "PENDING",
                "requiresCableRemovalVerification": False,
                "relationship": relationship.as_record(), "events": self.events}

    async def native_remote_xpc_available(self, udid: str, timeout: float = 2) -> bool:
        services = []
        try:
            services = await self.backend.native_remote_services(udid, timeout)
            return bool(services)
        finally:
            close = getattr(self.backend, "close", None)
            if close:
                for service in services:
                    await close(service)


async def async_main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("connect", "enable-wireless", "verify-wireless"))
    parser.add_argument("--support", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--host-fingerprint", default="")
    parser.add_argument("--usb-trust-verified", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    manager = AppleDeviceTransportManager(args.support)
    if args.operation == "connect":
        from apple_device_pairing import MacIdentity
        _, fingerprint = MacIdentity(args.support).ensure()
        result = await manager.connect(args.target, host_fingerprint=fingerprint)
    elif args.operation == "enable-wireless":
        result = await manager.enable_wireless(
            args.target, args.host_fingerprint,
            usb_trust_verified=args.usb_trust_verified)
    else:
        result = await manager.verify_wireless(
            args.target, args.host_fingerprint, require_usb_absent=True)
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_suffix(args.output.suffix + ".tmp")
        temporary.write_text(encoded); os.chmod(temporary, 0o600); temporary.replace(args.output)
    print(encoded, end="")
    return 0 if result.get("status") in ("connected", "ready") else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))
