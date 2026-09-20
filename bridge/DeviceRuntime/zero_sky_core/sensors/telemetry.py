"""Bounded telemetry providers used by the existing privileged manager.

There is deliberately no background thread here.  The existing manager calls
``tick`` from its loop; monotonic deadlines make that call effectively free
between samples. Unsupported battery/thermal sources are reported explicitly
and never synthesized as zero-valued readings.
"""
from __future__ import annotations

import json
import os
import plistlib
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..health import CircuitBreaker, SensorState
from ..paths import RootlessPaths


@dataclass(frozen=True)
class SensorResult:
    state: SensorState
    samples: tuple[dict[str, Any], ...] = ()
    reason: str | None = None
    evidence: tuple[str, ...] = ()


def parse_elapsed(value: str) -> int:
    """Parse the portable ``ps etime`` form [[dd-]hh:]mm:ss."""
    raw = value.strip()
    days = 0
    if "-" in raw:
        day, raw = raw.split("-", 1)
        days = int(day)
    pieces = [int(part) for part in raw.split(":")]
    if len(pieces) == 2:
        hours, minutes, seconds = 0, pieces[0], pieces[1]
    elif len(pieces) == 3:
        hours, minutes, seconds = pieces
    else:
        raise ValueError("invalid elapsed value")
    if min(days, hours, minutes, seconds) < 0 or minutes > 59 or seconds > 59:
        raise ValueError("invalid elapsed value")
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


class ProcessSensor:
    # A full iOS process list can exceed 600 rows. Persist the 256 most
    # resource-relevant rows; this is enough for the dashboard while keeping
    # 24-hour history and flash writes bounded.
    MAX_PROCESSES = 256

    def __init__(self, paths: RootlessPaths,
                 runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> None:
        self.paths, self.runner = paths, runner

    def _binary(self) -> Path | None:
        for candidate in ("/var/jb/usr/bin/ps", "/bin/ps"):
            path = self.paths.system(candidate)
            if path.is_file() and os.access(path, os.X_OK):
                return path
        return None

    def collect(self) -> SensorResult:
        binary = self._binary()
        if not binary:
            return SensorResult(SensorState.UNSUPPORTED,
                                reason="No approved ps command is executable")
        completed = self.runner(
            [str(binary), "-axo", "pid=,ppid=,uid=,%cpu=,rss=,etime=,comm="],
            check=False, capture_output=True, text=True, timeout=5,
            env={"PATH": "/var/jb/usr/bin:/usr/bin:/bin", "LANG": "C"})
        if completed.returncode != 0:
            raise RuntimeError(f"ps exited {completed.returncode}")
        samples: list[dict[str, Any]] = []
        rejected = 0
        for line in completed.stdout.splitlines()[:2048]:
            pieces = line.strip().split(None, 6)
            if len(pieces) != 7:
                rejected += 1
                continue
            try:
                pid, ppid, uid = (int(pieces[x]) for x in range(3))
                cpu, rss = float(pieces[3]), int(pieces[4])
                uptime = parse_elapsed(pieces[5])
                executable = pieces[6][:4096]
                if pid <= 0 or ppid < 0 or uid < 0 or not (0 <= cpu <= 100000) or rss < 0:
                    raise ValueError("invalid numeric range")
            except (ValueError, OverflowError):
                rejected += 1
                continue
            samples.append({"pid": pid, "ppid": ppid, "uid": uid,
                            "cpu": cpu, "memory_bytes": rss * 1024,
                            "process": Path(pieces[6]).name[:512],
                            "executable": executable,
                            "metadata": {"uptimeSeconds": uptime}})
        if not samples:
            raise RuntimeError("ps returned no valid process rows")
        samples.sort(key=lambda row: (-(row.get("cpu") or 0.0),
                                      -(row.get("memory_bytes") or 0),
                                      row["pid"]))
        samples = samples[: self.MAX_PROCESSES]
        return SensorResult(SensorState.RUNNING, tuple(samples),
                            evidence=(str(binary), f"rejectedRows={rejected}"))


class _ProviderJSON:
    MAX_BYTES = 16 * 1024

    def __init__(self, paths: RootlessPaths, name: str,
                 max_age_seconds: float = 600.0,
                 wall_clock: Callable[[], float] = time.time) -> None:
        self.paths, self.name = paths, name
        self.path = paths.provider_directory / f"{name}.json"
        self.max_age_seconds, self.wall_clock = max_age_seconds, wall_clock

    def read(self) -> dict[str, Any] | None:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return None
        expected_uid = 0 if self.paths.root == Path("/") else os.geteuid()
        if stat.st_uid != expected_uid or stat.st_mode & 0o022:
            raise ValueError("provider evidence has unsafe ownership or permissions")
        if stat.st_size <= 1 or stat.st_size > self.MAX_BYTES:
            raise ValueError("provider evidence size is invalid")
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("provider evidence must be an object")
        stamp = value.get("timestamp")
        if not isinstance(stamp, (int, float)) or isinstance(stamp, bool):
            raise ValueError("provider timestamp is invalid")
        age = self.wall_clock() - float(stamp)
        if age < -30 or age > self.max_age_seconds:
            raise ValueError("provider evidence is stale")
        return value


class BatterySensor:
    def __init__(self, paths: RootlessPaths,
                 runner: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
                 wall_clock: Callable[[], float] = time.time) -> None:
        self.paths, self.runner = paths, runner
        self.provider = _ProviderJSON(paths, "battery", wall_clock=wall_clock)

    @staticmethod
    def _validated(value: dict[str, Any], source: str) -> dict[str, Any]:
        level = value.get("levelPercent")
        charging = value.get("charging")
        if (not isinstance(level, (int, float)) or isinstance(level, bool) or
                not 0 <= float(level) <= 100 or not isinstance(charging, bool)):
            raise ValueError("battery provider schema is invalid")
        return {"level": float(level), "charging": charging, "source": source,
                "metadata": {"providerTimestamp": float(value["timestamp"])}}

    def collect(self) -> SensorResult:
        provider = self.provider.read()
        if provider is not None:
            sample = self._validated(provider, str(provider.get("source") or "provider-json")[:128])
            return SensorResult(SensorState.RUNNING, (sample,), evidence=(str(self.provider.path),))
        ioreg = self.paths.system("/usr/sbin/ioreg")
        if ioreg.is_file() and os.access(ioreg, os.X_OK):
            completed = self.runner([str(ioreg), "-a", "-r", "-c", "AppleSmartBattery"],
                                    check=False, capture_output=True, timeout=5)
            if completed.returncode == 0 and completed.stdout:
                try:
                    payload = plistlib.loads(completed.stdout)
                    node = payload[0] if isinstance(payload, list) and payload else {}
                    current, maximum = node.get("CurrentCapacity"), node.get("MaxCapacity")
                    charging = node.get("IsCharging")
                    if (isinstance(current, int) and isinstance(maximum, int) and maximum > 0
                            and isinstance(charging, bool)):
                        sample = {"level": max(0.0, min(100.0, current * 100.0 / maximum)),
                                  "charging": charging, "source": "AppleSmartBattery",
                                  "metadata": {}}
                        return SensorResult(SensorState.RUNNING, (sample,), evidence=(str(ioreg),))
                except (ValueError, plistlib.InvalidFileException, TypeError):
                    pass
        return SensorResult(SensorState.UNSUPPORTED,
                            reason="No validated battery observation is available")


class ThermalSensor:
    STATES = {"Nominal", "Fair", "Serious", "Critical"}

    def __init__(self, paths: RootlessPaths,
                 wall_clock: Callable[[], float] = time.time) -> None:
        self.provider = _ProviderJSON(paths, "thermal", wall_clock=wall_clock)

    def collect(self) -> SensorResult:
        provider = self.provider.read()
        if provider is None:
            return SensorResult(SensorState.UNSUPPORTED,
                                reason="No reviewed thermal state provider is installed")
        state = provider.get("state")
        if state not in self.STATES:
            raise ValueError("thermal provider state is invalid")
        sample = {"state": state,
                  "source": str(provider.get("source") or "provider-json")[:128],
                  "metadata": {"providerTimestamp": float(provider["timestamp"])}}
        return SensorResult(SensorState.RUNNING, (sample,), evidence=(str(self.provider.path),))


class DeviceHealthSensor:
    def __init__(self, paths: RootlessPaths, store: Any,
                 uptime: Callable[[], float]) -> None:
        self.paths, self.store, self.uptime = paths, store, uptime

    def collect(self) -> SensorResult:
        usage = shutil.disk_usage(self.paths.state_directory)
        try:
            db_size = self.paths.database_path.stat().st_size
        except OSError:
            db_size = 0
        sensor_rows = self.store.sensor_health()
        degraded = sum(1 for row in sensor_rows
                       if row.get("state") in (SensorState.DEGRADED.value,
                                               SensorState.FAILED.value))
        samples = (
            {"metric": "storage.free_bytes", "value_real": float(usage.free)},
            {"metric": "storage.total_bytes", "value_real": float(usage.total)},
            {"metric": "database.bytes", "value_real": float(db_size)},
            {"metric": "core.uptime_seconds", "value_real": max(0.0, self.uptime())},
            {"metric": "sensors.degraded_count", "value_real": float(degraded)},
            {"metric": "database.integrity", "value_text": self.store.integrity()},
        )
        return SensorResult(SensorState.RUNNING, samples)


@dataclass
class _ScheduledSensor:
    name: str
    interval: float
    collect: Callable[[], SensorResult]
    persist: Callable[[SensorResult, float], None]
    breaker: CircuitBreaker
    next_due: float = 0.0
    last_result: SensorResult | None = None


class TelemetryCoordinator:
    """Runs bounded collectors on deadlines without a second polling loop."""

    def __init__(self, paths: RootlessPaths, store: Any,
                 uptime: Callable[[], float], monotonic: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time,
                 intervals: dict[str, float] | None = None) -> None:
        self.paths, self.store = paths, store
        self.monotonic, self.wall_clock = monotonic, wall_clock
        configured = {"process": 60.0, "battery": 300.0,
                      "thermal": 300.0, "device_health": 600.0,
                      "network": 60.0, "privacy": 60.0,
                      "crash": 300.0, "conflict": 300.0,
                      "notification": 300.0}
        configured.update(intervals or {})
        # Local import avoids a module cycle: activity collectors share the
        # small SensorResult value type defined above.
        from .activity import NetworkSensor, PrivacySensor
        from .recovery import ConflictSensor, CrashSensor
        from ..intelligence import NotificationSensor
        process = ProcessSensor(paths)
        battery = BatterySensor(paths, wall_clock=wall_clock)
        thermal = ThermalSensor(paths, wall_clock=wall_clock)
        health = DeviceHealthSensor(paths, store, uptime)
        network = NetworkSensor(paths)
        privacy = PrivacySensor(paths, wall_clock=wall_clock)
        crash = CrashSensor(paths)
        conflict = ConflictSensor(paths, wall_clock=wall_clock)
        notification = NotificationSensor(paths, wall_clock=wall_clock)

        def persist_privacy(result: SensorResult, _stamp: float) -> None:
            newest = store.latest_timestamp("privacy_events")
            rows = [row for row in result.samples
                    if newest is None or float(row["timestamp"]) > newest]
            store.record_privacy_events(rows)
        self.sensors: dict[str, _ScheduledSensor] = {
            "process": _ScheduledSensor("process", configured["process"], process.collect,
                lambda r, t: store.record_process_samples(r.samples, t), CircuitBreaker("process")),
            "battery": _ScheduledSensor("battery", configured["battery"], battery.collect,
                lambda r, t: store.record_battery_sample(r.samples[0], t), CircuitBreaker("battery")),
            "thermal": _ScheduledSensor("thermal", configured["thermal"], thermal.collect,
                lambda r, t: store.record_thermal_sample(r.samples[0], t), CircuitBreaker("thermal")),
            "device_health": _ScheduledSensor("device_health", configured["device_health"], health.collect,
                lambda r, t: store.record_health_samples(r.samples, t), CircuitBreaker("device_health")),
            "network": _ScheduledSensor("network", configured["network"], network.collect,
                lambda r, t: store.record_network_events(r.samples, t), CircuitBreaker("network")),
            "privacy": _ScheduledSensor("privacy", configured["privacy"], privacy.collect,
                persist_privacy, CircuitBreaker("privacy")),
            "crash": _ScheduledSensor("crash", configured["crash"], crash.collect,
                lambda r, t: store.record_crashes(r.samples), CircuitBreaker("crash")),
            "conflict": _ScheduledSensor("conflict", configured["conflict"], conflict.collect,
                lambda r, t: store.replace_hook_conflicts(r.samples, t), CircuitBreaker("conflict")),
            "notification": _ScheduledSensor(
                "notification", configured["notification"], notification.collect,
                lambda r, t: store.record_notification_events(r.samples),
                CircuitBreaker("notification")),
        }
        self._next_retention = 0.0
        self._retention_seconds = self._load_retention()

    def _load_retention(self) -> dict[str, float]:
        """Read bounded user policy, retaining safe defaults on any error."""
        values = {"process_samples": 24 * 3600.0,
                  "battery_samples": 30 * 86400.0,
                  "thermal_samples": 30 * 86400.0,
                  "health_samples": 30 * 86400.0,
                  "network_events": 7 * 86400.0,
                  "network_snapshots": 7 * 86400.0,
                  "privacy_events": 30 * 86400.0,
                  "notification_events": 30 * 86400.0,
                  "crashes": 30 * 86400.0}
        path = self.paths.config_directory / "retention.json"
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            units = {"processHours": ("process_samples", 3600.0, 1, 168),
                     "batteryDays": ("battery_samples", 86400.0, 1, 365),
                     "thermalDays": ("thermal_samples", 86400.0, 1, 365),
                     "healthDays": ("health_samples", 86400.0, 1, 365),
                     "crashDays": ("crashes", 86400.0, 1, 365)}
            units.update({"networkDays": ("network_events", 86400.0, 1, 90),
                          "privacyDays": ("privacy_events", 86400.0, 1, 365)})
            units["notificationDays"] = ("notification_events", 86400.0, 1, 365)
            if not isinstance(payload, dict):
                return values
            for key, (table, multiplier, minimum, maximum) in units.items():
                raw = payload.get(key)
                if isinstance(raw, int) and not isinstance(raw, bool) and minimum <= raw <= maximum:
                    values[table] = raw * multiplier
            values["network_snapshots"] = values["network_events"]
        except (OSError, ValueError, TypeError):
            pass
        return values

    def _apply_retention(self, monotonic_now: float, wall_now: float) -> None:
        if monotonic_now < self._next_retention:
            return
        # One bounded batch per table every hour keeps pace with the maximum
        # 256-row/minute process history without a large daily delete burst.
        self._next_retention = monotonic_now + 3600.0
        for table, age in self._retention_seconds.items():
            self.store.apply_retention(table, wall_now - age, batch_size=25000)

    def tick(self, now: float | None = None) -> int:
        moment = self.monotonic() if now is None else float(now)
        wall_now = self.wall_clock()
        self._apply_retention(moment, wall_now)
        ran = 0
        for scheduled in self.sensors.values():
            if moment < scheduled.next_due:
                continue
            scheduled.next_due = moment + max(1.0, scheduled.interval)
            if not scheduled.breaker.allow(moment):
                self.store.update_sensor_health(scheduled.name, SensorState.FAILED.value,
                                                error="collector circuit breaker is open")
                continue
            try:
                result = scheduled.collect()
                scheduled.last_result = result
                if result.state == SensorState.RUNNING:
                    scheduled.persist(result, wall_now)
                    scheduled.breaker.success()
                    self.store.update_sensor_health(scheduled.name, result.state.value, success=True)
                elif result.state == SensorState.UNSUPPORTED:
                    scheduled.breaker.success()
                    self.store.update_sensor_health(scheduled.name, result.state.value,
                                                    error=result.reason)
                else:
                    scheduled.breaker.failure(moment)
                    self.store.update_sensor_health(scheduled.name, result.state.value,
                                                    error=result.reason)
            except Exception as error:
                scheduled.breaker.failure(moment)
                state = (SensorState.FAILED if not scheduled.breaker.allow(moment)
                         else SensorState.DEGRADED)
                self.store.update_sensor_health(scheduled.name, state.value,
                                                error=str(error)[:2048])
            ran += 1
        return ran

    def capability_states(self) -> dict[str, tuple[str, str]]:
        mapping = {"process": "processInspection", "battery": "batteryMonitoring",
                   "thermal": "thermalMonitoring", "device_health": "deviceHealth",
                   "network": "networkObservation", "privacy": "privacyObservation",
                   "crash": "crashObservation", "conflict": "tweakConflictAnalysis"}
        mapping["notification"] = "notificationObservation"
        result: dict[str, tuple[str, str]] = {}
        for name, scheduled in self.sensors.items():
            if not scheduled.last_result:
                continue
            value = scheduled.last_result
            capability = (("MonitorOnly" if name in {"conflict", "notification"} else "Supported")
                          if value.state == SensorState.RUNNING
                          else value.state.value)
            result[mapping[name]] = (capability, value.reason or "Validated live telemetry is available")
        return result
