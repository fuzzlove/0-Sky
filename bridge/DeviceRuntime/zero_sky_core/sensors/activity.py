"""Bounded network and privacy observation for Phase 3.

Network observation uses Apple's read-only libproc interfaces through ctypes so
it does not require another executable, packet capture, injection, or a new
privilege mechanism. Privacy observations are accepted only from a reviewed,
root-owned provider because current SRDs expose no trustworthy native timeline.
"""
from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import plistlib
import re
import socket
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..health import SensorState
from ..paths import RootlessPaths
from .telemetry import SensorResult

# Darwin 64-bit layouts from <sys/proc_info.h>. Every returned buffer is checked
# against the full expected size before these offsets are read.
PROC_PIDLISTFDS = 1
PROC_PIDFDSOCKETINFO = 3
PROX_FDTYPE_SOCKET = 2
SOCKET_FDINFO_SIZE = 792
PSI_OFFSET = 24
SOI_PROTOCOL = PSI_OFFSET + 156
SOI_FAMILY = PSI_OFFSET + 160
SOI_RCV_CC = PSI_OFFSET + 184
SOI_SND_CC = PSI_OFFSET + 208
SOI_KIND = PSI_OFFSET + 232
SOI_PROTO = PSI_OFFSET + 240
INSI_FPORT = SOI_PROTO
INSI_LPORT = SOI_PROTO + 4
INSI_VFLAG = SOI_PROTO + 24
INSI_FADDR = SOI_PROTO + 32
INSI_LADDR = SOI_PROTO + 48
TCPSI_STATE = SOI_PROTO + 80
SOCKINFO_IN = 1
SOCKINFO_TCP = 2
INI_IPV4 = 1
INI_IPV6 = 2
MAX_PIDS = 4096
MAX_FDS = 4096
MAX_CONNECTIONS = 2048
BUNDLE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def _i32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("=i", data, offset)[0])


def _u32(data: bytes, offset: int) -> int:
    return int(struct.unpack_from("=I", data, offset)[0])


def parse_socket_buffer(data: bytes) -> dict[str, Any] | None:
    """Parse one validated Darwin socket_fdinfo buffer."""
    if len(data) < SOCKET_FDINFO_SIZE:
        return None
    kind, protocol_number = _i32(data, SOI_KIND), _i32(data, SOI_PROTOCOL)
    if kind == SOCKINFO_TCP:
        protocol, state = "tcp", _i32(data, TCPSI_STATE)
    elif kind == SOCKINFO_IN and protocol_number == socket.IPPROTO_UDP:
        protocol, state = "udp", 0
    else:
        return None
    flags = data[INSI_VFLAG]
    try:
        if flags & INI_IPV4:
            family, width = socket.AF_INET, 4
            # in4in6_addr stores the IPv4 address in its final four bytes.
            foreign = data[INSI_FADDR + 12:INSI_FADDR + 16]
            local = data[INSI_LADDR + 12:INSI_LADDR + 16]
            family_name = "IPv4"
        elif flags & INI_IPV6:
            family, width = socket.AF_INET6, 16
            foreign = data[INSI_FADDR:INSI_FADDR + 16]
            local = data[INSI_LADDR:INSI_LADDR + 16]
            family_name = "IPv6"
        else:
            return None
        remote_address = socket.inet_ntop(family, foreign[:width])
        local_address = socket.inet_ntop(family, local[:width])
    except (OSError, ValueError):
        return None
    remote_port = socket.ntohs(_u32(data, INSI_FPORT) & 0xFFFF)
    local_port = socket.ntohs(_u32(data, INSI_LPORT) & 0xFFFF)
    if remote_port <= 0 or remote_address in ("0.0.0.0", "::"):
        return None
    address = ipaddress.ip_address(remote_address.split("%", 1)[0])
    scope = ("loopback" if address.is_loopback else "link-local" if address.is_link_local
             else "lan" if address.is_private else "public")
    return {"protocol": protocol, "family": family_name,
            "localAddress": local_address, "localPort": local_port,
            "remoteAddress": remote_address, "remotePort": remote_port,
            "state": state, "scope": scope,
            "receiveQueueBytes": _u32(data, SOI_RCV_CC),
            "sendQueueBytes": _u32(data, SOI_SND_CC)}


class LibprocBackend:
    def __init__(self) -> None:
        self.lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        self.lib.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_listallpids.restype = ctypes.c_int
        self.lib.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        self.lib.proc_pidpath.restype = ctypes.c_int
        self.lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64,
                                          ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidinfo.restype = ctypes.c_int
        self.lib.proc_pidfdinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                            ctypes.c_void_p, ctypes.c_int]
        self.lib.proc_pidfdinfo.restype = ctypes.c_int

    def pids(self) -> list[int]:
        values = (ctypes.c_int * MAX_PIDS)()
        count = self.lib.proc_listallpids(values, ctypes.sizeof(values))
        if count < 0:
            raise OSError(ctypes.get_errno(), "proc_listallpids failed")
        return [int(values[x]) for x in range(min(count, MAX_PIDS)) if values[x] > 0]

    def path(self, pid: int) -> str | None:
        buffer = ctypes.create_string_buffer(4096)
        if self.lib.proc_pidpath(pid, buffer, len(buffer)) <= 0:
            return None
        value = os.fsdecode(buffer.value)
        return value if value.startswith("/") else None

    def fds(self, pid: int) -> list[tuple[int, int]]:
        needed = self.lib.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, None, 0)
        if needed <= 0:
            return []
        needed = min(needed, MAX_FDS * 8)
        buffer = ctypes.create_string_buffer(needed)
        got = self.lib.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer, needed)
        if got <= 0:
            return []
        return [struct.unpack_from("=iI", buffer.raw, offset)
                for offset in range(0, got - 7, 8)]

    def socket(self, pid: int, fd: int) -> bytes | None:
        buffer = ctypes.create_string_buffer(SOCKET_FDINFO_SIZE)
        got = self.lib.proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO,
                                      buffer, len(buffer))
        return bytes(buffer.raw) if got >= SOCKET_FDINFO_SIZE else None


class NetworkSensor:
    def __init__(self, paths: RootlessPaths,
                 backend_factory: Callable[[], Any] = LibprocBackend) -> None:
        self.paths, self.backend_factory = paths, backend_factory
        self._bundle_cache: dict[str, str | None] = {}

    def _bundle_id(self, executable: str) -> str | None:
        if executable in self._bundle_cache:
            return self._bundle_cache[executable]
        path = Path(executable)
        app: Path | None = None
        for parent in (path, *path.parents):
            if parent.name.endswith(".app"):
                app = parent
                break
        value: str | None = None
        if app:
            try:
                info = plistlib.loads((app / "Info.plist").read_bytes())
                candidate = info.get("CFBundleIdentifier")
                if isinstance(candidate, str) and BUNDLE_ID.fullmatch(candidate):
                    value = candidate
            except (OSError, ValueError, plistlib.InvalidFileException):
                pass
        self._bundle_cache[executable] = value
        return value

    def collect(self) -> SensorResult:
        try:
            backend = self.backend_factory()
        except OSError as error:
            return SensorResult(SensorState.UNSUPPORTED,
                                reason=f"libproc socket observation unavailable: {error}")
        rows: list[dict[str, Any]] = []
        seen: set[tuple[Any, ...]] = set()
        denied = 0
        for pid in backend.pids():
            executable = backend.path(pid)
            if not executable:
                denied += 1
                continue
            for fd, kind in backend.fds(pid):
                if kind != PROX_FDTYPE_SOCKET:
                    continue
                raw = backend.socket(pid, fd)
                parsed = parse_socket_buffer(raw) if raw else None
                if not parsed:
                    continue
                key = (pid, parsed["protocol"], parsed["localPort"],
                       parsed["remoteAddress"], parsed["remotePort"])
                if key in seen:
                    continue
                seen.add(key)
                rows.append({"pid": pid, "bundle_id": self._bundle_id(executable),
                            "destination": parsed["remoteAddress"],
                            "protocol": parsed["protocol"], "port": parsed["remotePort"],
                            "decision": "Observed",
                            "metadata": {"executable": executable, **parsed,
                                         "attribution": "directly-observed-current-socket",
                                         "transport": "unknown"}})
                if len(rows) >= MAX_CONNECTIONS:
                    break
            if len(rows) >= MAX_CONNECTIONS:
                break
        return SensorResult(SensorState.RUNNING, tuple(rows),
                            reason="Current sockets are observable; historical closed flows and enforcement are unavailable",
                            evidence=("libproc", f"unreadableProcesses={denied}"))


class PrivacySensor:
    RESOURCES = {"camera", "microphone", "location", "clipboard", "contacts",
                 "photos", "bluetooth", "local-network"}
    DECISIONS = {"Observed", "Allowed", "Denied", "Prompted", "Unknown"}
    MAX_BYTES = 256 * 1024
    MAX_EVENTS = 512

    def __init__(self, paths: RootlessPaths,
                 wall_clock: Callable[[], float] = time.time) -> None:
        self.paths, self.wall_clock = paths, wall_clock
        self.path = paths.provider_directory / "privacy-events.json"

    def collect(self) -> SensorResult:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return SensorResult(SensorState.UNSUPPORTED,
                                reason="No reviewed privacy event provider is installed")
        expected_uid = 0 if self.paths.root == Path("/") else os.geteuid()
        if stat.st_uid != expected_uid or stat.st_mode & 0o022 or not 1 < stat.st_size <= self.MAX_BYTES:
            raise ValueError("privacy provider evidence has unsafe ownership, permissions, or size")
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
            raise ValueError("privacy provider schema is invalid")
        generated = payload.get("timestamp")
        if (not isinstance(generated, (int, float)) or isinstance(generated, bool) or
                not -30 <= self.wall_clock() - float(generated) <= 600):
            raise ValueError("privacy provider evidence is stale")
        rows: list[dict[str, Any]] = []
        for event in payload["events"][:self.MAX_EVENTS]:
            if not isinstance(event, dict):
                continue
            timestamp, resource = event.get("timestamp"), event.get("resource")
            decision = event.get("decision", "Observed")
            bundle = event.get("bundleId")
            if (not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool) or
                    resource not in self.RESOURCES or decision not in self.DECISIONS or
                    (bundle is not None and (not isinstance(bundle, str) or not BUNDLE_ID.fullmatch(bundle)))):
                continue
            rows.append({"timestamp": float(timestamp), "bundle_id": bundle,
                         "pid": event.get("pid") if isinstance(event.get("pid"), int) else None,
                         "resource": resource,
                         "action": str(event.get("action") or "access")[:128],
                         "decision": decision,
                         "metadata": {"provider": str(payload.get("provider") or "reviewed-json")[:128]}})
        return SensorResult(SensorState.RUNNING, tuple(rows),
                            evidence=(str(self.path),))
