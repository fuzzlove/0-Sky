"""Local notification metadata and reversible permission timeouts."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Protocol

from .automation import BUNDLE_ID, PolicyError
from .database import EventStore
from .health import SensorState
from .paths import RootlessPaths
from .sensors.telemetry import SensorResult


class NotificationSensor:
    """Consume metadata only from a reviewed, root-owned local provider."""
    MAX_BYTES = 256 * 1024
    MAX_EVENTS = 1024
    SENSITIVE_KEYS = frozenset({
        "body", "title", "subtitle", "content", "message", "text", "attachment",
        "userInfo", "clipboard", "token",
    })

    def __init__(self, paths: RootlessPaths, wall_clock=time.time) -> None:
        self.paths, self.wall_clock = paths, wall_clock
        self.path = paths.provider_directory / "notifications.json"

    def collect(self) -> SensorResult:
        try:
            file_stat = self.path.stat()
        except FileNotFoundError:
            return SensorResult(SensorState.UNSUPPORTED,
                                reason="No reviewed local notification metadata provider is installed")
        expected_uid = 0 if self.paths.root == Path("/") else os.geteuid()
        if (file_stat.st_uid != expected_uid or file_stat.st_mode & 0o022 or
                not 1 < file_stat.st_size <= self.MAX_BYTES):
            raise ValueError("notification provider evidence has unsafe ownership, permissions, or size")
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("events"), list):
            raise ValueError("notification provider schema is invalid")
        generated = payload.get("timestamp")
        if (not isinstance(generated, (int, float)) or isinstance(generated, bool) or
                not -30 <= self.wall_clock() - float(generated) <= 600):
            raise ValueError("notification provider evidence is stale")
        provider = str(payload.get("provider") or "reviewed-local-metadata")[:64]
        rows: list[dict[str, Any]] = []
        for event in payload["events"][:self.MAX_EVENTS]:
            if not isinstance(event, dict) or self.SENSITIVE_KEYS.intersection(event):
                continue
            if set(event) - {"timestamp", "bundleId", "categoryId", "eventId"}:
                continue
            timestamp, bundle_id = event.get("timestamp"), event.get("bundleId")
            category = event.get("categoryId")
            event_id = event.get("eventId")
            if (not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool) or
                    not isinstance(bundle_id, str) or not BUNDLE_ID.fullmatch(bundle_id) or
                    (category is not None and (not isinstance(category, str) or len(category) > 128)) or
                    (event_id is not None and (not isinstance(event_id, str) or len(event_id) > 128))):
                continue
            fingerprint = hashlib.sha256(
                f"{provider}\0{float(timestamp):.6f}\0{bundle_id}\0{category or ''}\0{event_id or ''}".encode()
            ).hexdigest()
            rows.append({"timestamp": float(timestamp), "bundle_id": bundle_id,
                         "category_id": category, "source": provider,
                         "fingerprint": fingerprint,
                         "metadata": {"contentStored": False}})
        return SensorResult(SensorState.RUNNING, tuple(rows),
                            reason="Local metadata only; notification content is neither accepted nor stored",
                            evidence=(str(self.path),))


class PermissionProvider(Protocol):
    name: str
    supported_resources: set[str]

    def get_policy(self, bundle_id: str, resource: str) -> str: ...
    def set_policy(self, bundle_id: str, resource: str, policy: str) -> None: ...


class PermissionTimeoutCoordinator:
    RESOURCES = frozenset({"camera", "microphone", "location", "clipboard",
                           "contacts", "photos", "bluetooth", "local-network"})
    POLICIES = frozenset({"System Default", "Allow", "Ask", "Block"})
    DURATIONS = {"once": None, "5 minutes": 300, "15 minutes": 900,
                 "1 hour": 3600, "until app exits": None,
                 "until screen locks": None}

    def __init__(self, store: EventStore, provider: PermissionProvider | None = None) -> None:
        self.store, self.provider = store, provider

    def capability(self) -> dict[str, Any]:
        if self.provider is None:
            return {"state": "MonitorOnly",
                    "reason": "Permission history may be observed, but no reviewed permission-enforcement provider is installed",
                    "resources": {name: "Unsupported" for name in sorted(self.RESOURCES)},
                    "durations": list(self.DURATIONS)}
        return {"state": "Supported", "reason": "A reviewed reversible permission provider is installed",
                "provider": self.provider.name,
                "resources": {name: ("Supported" if name in self.provider.supported_resources
                                     else "Unsupported") for name in sorted(self.RESOURCES)},
                "durations": list(self.DURATIONS)}

    def create(self, bundle_id: Any, resource: Any, policy: Any,
               duration: Any, now: float | None = None) -> dict[str, Any]:
        if not isinstance(bundle_id, str) or not BUNDLE_ID.fullmatch(bundle_id):
            raise PolicyError("INVALID_BUNDLE_ID", "bundleID is invalid")
        if resource not in self.RESOURCES or policy not in self.POLICIES or duration not in self.DURATIONS:
            raise PolicyError("INVALID_PERMISSION_POLICY", "permission resource, policy, or duration is invalid")
        if self.provider is None or resource not in self.provider.supported_resources:
            raise PolicyError("UNSUPPORTED_PERMISSION", "no reviewed enforcement provider supports this resource")
        stamp = time.time() if now is None else float(now)
        previous = self.provider.get_policy(bundle_id, resource)
        if previous not in self.POLICIES:
            raise PolicyError("PROVIDER_ERROR", "provider returned an invalid current policy")
        seconds = self.DURATIONS[duration]
        expires = stamp + seconds if seconds is not None else None
        condition = ({"once": "nextAccess", "until app exits": "applicationExit",
                      "until screen locks": "screenLock"}.get(duration))
        self.provider.set_policy(bundle_id, resource, policy)
        identifier = self.store.create_permission_timeout(
            bundle_id=bundle_id, resource=resource, requested_policy=policy,
            previous_policy=previous, duration=duration, expires_at=expires,
            expiration_condition=condition, provider=self.provider.name)
        return {"id": identifier, "bundleID": bundle_id, "resource": resource,
                "policy": policy, "previousPolicy": previous, "duration": duration,
                "expiresAt": expires, "expirationCondition": condition,
                "state": "Active", "reversible": True}

    def revert(self, timeout_id: int, state: str = "Reverted") -> dict[str, Any]:
        rows = [row for row in self.store.permission_timeouts(active_only=True)
                if row["id"] == int(timeout_id)]
        if len(rows) != 1:
            raise PolicyError("TIMEOUT_NOT_ACTIVE", "permission timeout is not active")
        row = rows[0]
        if self.provider is None or row["resource"] not in self.provider.supported_resources:
            raise PolicyError("PROVIDER_UNAVAILABLE", "permission cannot be safely reverted without its provider")
        try:
            self.provider.set_policy(row["bundle_id"], row["resource"], row["previous_policy"])
            self.store.finish_permission_timeout(row["id"], state)
        except Exception as error:
            try:
                self.store.finish_permission_timeout(row["id"], "Failed", str(error))
            except ValueError:
                pass
            raise PolicyError("REVERT_FAILED", "permission provider failed to restore the prior policy") from error
        return {"id": row["id"], "bundleID": row["bundle_id"],
                "resource": row["resource"], "restoredPolicy": row["previous_policy"],
                "state": state, "reversible": False}

    def maintain(self, now: float | None = None, event: dict[str, Any] | None = None) -> int:
        stamp = time.time() if now is None else float(now)
        count = 0
        for row in self.store.permission_timeouts(active_only=True):
            due = row.get("expires_at") is not None and float(row["expires_at"]) <= stamp
            if event and row.get("expiration_condition") == event.get("type"):
                due = (row["expiration_condition"] != "applicationExit" or
                       event.get("bundleID") == row["bundle_id"])
            if due:
                self.revert(row["id"], "Expired"); count += 1
        return count
