"""Versioned, bounded 0-Sky core IPC request/response model."""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

PROTOCOL_VERSION = 1
MAX_REQUEST_BYTES = 64 * 1024
READ_OPERATIONS = frozenset({"getStatus", "getCapabilities", "getSensorHealth",
                             "getRecentChanges", "getProcesses", "getBatteryState",
                             "getThermalState", "getDeviceHealth",
                             "getTelemetryHistory", "getConnections",
                             "getPrivacyEvents", "getPrivacySummary",
                             "getPackages", "getPackageDetail", "getCrashes",
                             "getConflicts", "getTweakHooks", "getRecoveryStatus",
                             "getSnapshotCapability", "getSnapshotApps",
                             "getSnapshots", "getSnapshotDetail",
                             "getProfileCapability", "getProfiles",
                             "getProfileTransactions", "getAutomationRules",
                             "getAutomationHistory", "getFreezeCapability",
                             "getFrozenApps", "getStorageIntelligence",
                             "getNotificationAnalytics", "getNotificationEvents",
                             "getPermissionTimeoutCapability", "getPermissionTimeouts",
                             "getControlCenterSummary", "getHealthTimeline",
                             "getRecoveryOptions"})
WRITE_OPERATIONS = frozenset({"restartNormally", "disableRecentTweaks",
                              "disableSelectedTweak", "startWithoutTweaks",
                              "createSnapshot", "restoreSnapshot",
                              "deleteSnapshot", "undoChange", "saveProfile",
                              "applyProfile", "saveAutomationRule",
                              "setAutomationRuleEnabled", "emitAutomationEvent",
                              "freezeApp", "temporarilyActivateApp", "unfreezeApp"})
WRITE_OPERATIONS = WRITE_OPERATIONS | frozenset({"setTemporaryPermission",
                                                  "revertPermissionTimeout",
                                                  "publishPowerTelemetry"})
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class IPCValidationError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class IPCRequest:
    request_id: str
    operation: str
    timestamp: float
    parameters: dict[str, Any]
    access: str


def validate_request(payload: Any, now: float | None = None) -> IPCRequest:
    if not isinstance(payload, dict):
        raise IPCValidationError("INVALID_REQUEST", "request must be an object")
    try:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise IPCValidationError("INVALID_REQUEST", "request is not JSON serializable") from error
    if len(encoded) > MAX_REQUEST_BYTES:
        raise IPCValidationError("REQUEST_TOO_LARGE", "request exceeds the size limit")
    if payload.get("protocolVersion") != PROTOCOL_VERSION:
        raise IPCValidationError("UNSUPPORTED_PROTOCOL", "unsupported protocol version")
    request_id = payload.get("requestId")
    operation = payload.get("operation")
    timestamp = payload.get("timestamp")
    parameters = payload.get("parameters")
    if not isinstance(request_id, str) or not IDENTIFIER.fullmatch(request_id):
        raise IPCValidationError("INVALID_REQUEST_ID", "invalid request ID")
    if not isinstance(operation, str) or not IDENTIFIER.fullmatch(operation):
        raise IPCValidationError("INVALID_OPERATION", "invalid operation")
    if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
        raise IPCValidationError("INVALID_TIMESTAMP", "timestamp must be numeric")
    current = time.time() if now is None else now
    if abs(float(timestamp) - current) > 300:
        raise IPCValidationError("STALE_REQUEST", "timestamp is outside the five-minute window")
    if not isinstance(parameters, dict):
        raise IPCValidationError("INVALID_PARAMETERS", "parameters must be an object")
    if operation in READ_OPERATIONS:
        access = "read"
    elif operation in WRITE_OPERATIONS:
        access = "write"
    else:
        raise IPCValidationError("OPERATION_NOT_APPROVED", "operation is not approved")
    return IPCRequest(request_id, operation, float(timestamp), parameters, access)


def response(request_id: str, success: bool, result: Any = None,
             error_code: str | None = None, error_message: str | None = None) -> dict[str, Any]:
    return {"protocolVersion": PROTOCOL_VERSION, "requestId": request_id,
            "timestamp": time.time(), "success": bool(success),
            "result": result if success else None,
            "errorCode": None if success else (error_code or "INTERNAL_ERROR"),
            "errorMessage": None if success else (error_message or "Operation failed")}
