"""Sensor health and fail-safe circuit-breaker primitives."""
from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, TypeVar


class SensorState(str, Enum):
    RUNNING = "Running"
    DEGRADED = "Degraded"
    UNSUPPORTED = "Unsupported"
    FAILED = "Failed"


@dataclass
class CircuitBreaker:
    component: str
    failure_threshold: int = 5
    cooldown_seconds: float = 300.0
    failures: int = 0
    opened_at: float | None = None

    def allow(self, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        if self.opened_at is None:
            return True
        if current - self.opened_at >= self.cooldown_seconds:
            self.failures = 0
            self.opened_at = None
            return True
        return False

    def success(self) -> None:
        self.failures = 0
        self.opened_at = None

    def failure(self, now: float | None = None) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_at = time.monotonic() if now is None else now


T = TypeVar("T")


def protected_call(breaker: CircuitBreaker, callback: Callable[[], T]) -> T:
    if not breaker.allow():
        raise RuntimeError(f"{breaker.component} circuit breaker is open")
    try:
        value = callback()
    except Exception:
        breaker.failure()
        raise
    breaker.success()
    return value
