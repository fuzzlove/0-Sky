"""Bounded structured logging with recursive secret redaction."""
from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


LEVELS = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"}
COMPONENTS = {"CORE", "IPC", "NETWORK", "PRIVACY", "BATTERY", "THERMAL",
              "PROCESS", "PACKAGE", "SNAPSHOT", "AUTOMATION", "RECOVERY"}
SENSITIVE = ("password", "passwd", "secret", "token", "authorization",
             "cookie", "keychain", "clipboard", "notification_content")


def _redact(value: Any, key: str = "") -> Any:
    if any(marker in key.lower() for marker in SENSITIVE):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item) for item in value]
    if isinstance(value, str) and len(value) > 8192:
        return value[:8192] + "…"
    return value


class StructuredLogger:
    def __init__(self, path: Path, max_bytes: int = 2 * 1024 * 1024) -> None:
        self.path = path
        self.max_bytes = max(64 * 1024, int(max_bytes))
        self._lock = threading.Lock()

    def _rotate(self) -> None:
        try:
            if self.path.stat().st_size < self.max_bytes:
                return
        except FileNotFoundError:
            return
        previous = self.path.with_suffix(self.path.suffix + ".1")
        try:
            previous.unlink(missing_ok=True)
            os.replace(self.path, previous)
        except OSError:
            pass

    def log(self, level: str, component: str, message: str, **fields: Any) -> None:
        level = level.upper()
        component = component.upper()
        if level not in LEVELS:
            raise ValueError("invalid log level")
        if component not in COMPONENTS:
            raise ValueError("invalid log component")
        record = {"schemaVersion": 1, "timestamp": time.time(), "level": level,
                  "component": component, "message": str(message)[:2048],
                  "fields": _redact(fields)}
        line = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        with self._lock:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._rotate()
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
