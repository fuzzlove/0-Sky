"""Serialized Control install transaction and evidence contract."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
import threading
import time

try:
    from .control_install_policy import Decision
except ImportError:  # standalone PoC tests
    from control_install_policy import Decision


class InstallerBackend(Protocol):
    name: str

    def snapshot(self) -> object: ...
    def stage(self) -> object: ...
    def install(self, staged: object) -> None: ...
    def register(self) -> None: ...
    def configure(self) -> None: ...
    def verify(self) -> dict[str, bool]: ...
    def rollback(self, snapshot: object) -> None: ...
    def verify_rollback(self, snapshot: object) -> bool: ...
    def cleanup(self, staged: object | None) -> None: ...


EVIDENCE = ("payload", "compatibility", "installation", "registration",
            "permissions", "dependencies", "launch", "link_communication")
_lock = threading.Lock()


@dataclass
class Result:
    result: str
    stage: str
    backend: str | None
    code: str
    explanation: str
    rollback: str = "NOT_APPLICABLE"
    evidence: dict[str, bool] = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def execute(decision: Decision, backend: InstallerBackend | None) -> Result:
    """Run one bounded transaction; the caller has verified the release IPA."""
    result = Result("BLOCKED", "PRECHECK", backend.name if backend else None,
                    decision.code, decision.explanation)

    def event(name: str, **fields: object) -> None:
        result.events.append({"event": name, "timestamp": int(time.time()), **fields})

    event("CONTROL_INSTALL_REQUESTED", action=decision.action)
    if decision.action == "BLOCK":
        return result
    if backend is None or backend.name != decision.backend:
        result.code = "BACKEND_MISMATCH"
        result.explanation = "Required paired installer backend is unavailable"
        return result
    if decision.action == "NO_ACTION":
        result.stage = "VERIFY"
        evidence = backend.verify()
        result.evidence = {key: evidence.get(key) is True for key in EVIDENCE}
        if all(result.evidence.values()):
            result.result = "ALREADY_INSTALLED_AND_VERIFIED"
            result.code = "CURRENT"
            event("CONTROL_INSTALL_VERIFIED", action="NO_ACTION")
        else:
            result.code = "HEALTH_CHANGED"
            result.explanation = "Control health changed during verification; retry repair"
        return result
    if not _lock.acquire(blocking=False):
        result.code = "INSTALL_IN_PROGRESS"
        result.explanation = "A Control installation is already in progress"
        return result
    snapshot = None
    staged = None
    modified = False
    try:
        event("CONTROL_PREFLIGHT_PASS")
        event("CONTROL_PAYLOAD_VERIFIED")
        event("CONTROL_COMPATIBILITY_PASS", status=decision.compatibility)
        snapshot = backend.snapshot()
        result.stage = "STAGE"
        staged = backend.stage()
        event("CONTROL_INSTALL_STARTED", backend=backend.name)
        result.stage = "INSTALL"
        modified = True
        backend.install(staged)
        event("CONTROL_INSTALL_COMPLETE")
        result.stage = "REGISTER"
        backend.register()
        event("CONTROL_REGISTRATION_COMPLETE")
        result.stage = "CONFIGURE"
        backend.configure()
        result.stage = "VERIFY"
        evidence = backend.verify()
        result.evidence = {key: evidence.get(key) is True for key in EVIDENCE}
        if not all(result.evidence.values()):
            missing = ", ".join(key for key, passed in result.evidence.items() if not passed)
            raise RuntimeError("Post-install evidence failed: " + missing)
        event("CONTROL_PERMISSION_CHECK_COMPLETE")
        event("CONTROL_HEALTHCHECK_PASS")
        result.stage = "COMMIT"
        result.result = "INSTALLED_AND_VERIFIED"
        result.code = "OK"
        result.explanation = "Control installation and health checks passed"
        event("CONTROL_INSTALL_VERIFIED", action=decision.action)
    except Exception as error:
        result.result = "FAILED"
        result.code = type(error).__name__.upper()
        result.explanation = str(error)[:500]
        event("CONTROL_INSTALL_FAILED", stage=result.stage, code=result.code)
        if modified:
            result.rollback = "FAILED"
            try:
                backend.rollback(snapshot)
                result.rollback = "VERIFIED" if backend.verify_rollback(snapshot) else "FAILED"
            except Exception:
                result.rollback = "FAILED"
            event("CONTROL_INSTALL_ROLLBACK", status=result.rollback)
    finally:
        try:
            backend.cleanup(staged)
        finally:
            _lock.release()
    return result
