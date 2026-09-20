"""Migrated, recoverable SQLite event store for 0-Sky."""
from __future__ import annotations

import datetime as dt
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 8

MIGRATION_1 = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  schema_version INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  timestamp REAL NOT NULL,
  component TEXT NOT NULL,
  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  payload_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_time ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_component_time ON events(component, timestamp DESC);
CREATE TABLE IF NOT EXISTS changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  timestamp REAL NOT NULL,
  component TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  previous_state_json TEXT,
  new_state_json TEXT,
  reversible INTEGER NOT NULL DEFAULT 0,
  transaction_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_changes_time ON changes(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_changes_target_time ON changes(target, timestamp DESC);
CREATE TABLE IF NOT EXISTS sensor_health (
  sensor TEXT PRIMARY KEY,
  schema_version INTEGER NOT NULL DEFAULT 1,
  state TEXT NOT NULL,
  last_success REAL,
  last_failure REAL,
  error TEXT,
  restart_count INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sensor_health_state ON sensor_health(state, updated_at DESC);
"""

MIGRATION_2 = """
CREATE TABLE IF NOT EXISTS network_events (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, timestamp REAL NOT NULL, bundle_id TEXT, pid INTEGER, destination TEXT, protocol TEXT, port INTEGER, bytes_sent INTEGER, bytes_received INTEGER, decision TEXT, metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_network_bundle_time ON network_events(bundle_id, timestamp DESC);
CREATE TABLE IF NOT EXISTS privacy_events (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, timestamp REAL NOT NULL, bundle_id TEXT, pid INTEGER, resource TEXT NOT NULL, action TEXT, decision TEXT, metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_privacy_resource_time ON privacy_events(resource, timestamp DESC);
CREATE TABLE IF NOT EXISTS process_samples (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, timestamp REAL NOT NULL, pid INTEGER NOT NULL, ppid INTEGER, uid INTEGER, process TEXT, executable TEXT, cpu REAL, memory_bytes INTEGER, wakeups INTEGER, metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_process_pid_time ON process_samples(pid, timestamp DESC);
CREATE TABLE IF NOT EXISTS battery_samples (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, timestamp REAL NOT NULL, level REAL, charging INTEGER, source TEXT, metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_battery_time ON battery_samples(timestamp DESC);
CREATE TABLE IF NOT EXISTS thermal_samples (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, timestamp REAL NOT NULL, state TEXT NOT NULL, source TEXT, metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_thermal_time ON thermal_samples(timestamp DESC);
CREATE TABLE IF NOT EXISTS health_samples (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, timestamp REAL NOT NULL, metric TEXT NOT NULL, value_real REAL, value_text TEXT, metadata_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_health_metric_time ON health_samples(metric, timestamp DESC);
CREATE TABLE IF NOT EXISTS crashes (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, timestamp REAL NOT NULL, process TEXT NOT NULL, bundle_id TEXT, report_path TEXT, evidence_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_crashes_process_time ON crashes(process, timestamp DESC);
CREATE TABLE IF NOT EXISTS tweak_hooks (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, updated_at REAL NOT NULL, process TEXT, image TEXT, symbol TEXT, package TEXT, evidence_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_hooks_process_symbol ON tweak_hooks(process, symbol);
CREATE TABLE IF NOT EXISTS conflicts (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, updated_at REAL NOT NULL, severity TEXT NOT NULL, target TEXT, evidence_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_conflicts_severity_time ON conflicts(severity, updated_at DESC);
CREATE TABLE IF NOT EXISTS app_snapshots (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, updated_at REAL NOT NULL, bundle_id TEXT NOT NULL, app_version TEXT, manifest_path TEXT NOT NULL, total_size INTEGER, manifest_sha256 TEXT, state TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_snapshots_bundle_time ON app_snapshots(bundle_id, created_at DESC);
CREATE TABLE IF NOT EXISTS automation_rules (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, updated_at REAL NOT NULL, name TEXT NOT NULL, enabled INTEGER NOT NULL, rule_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON automation_rules(enabled, updated_at DESC);
CREATE TABLE IF NOT EXISTS automation_runs (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, timestamp REAL NOT NULL, rule_id INTEGER, success INTEGER NOT NULL, result_json TEXT NOT NULL DEFAULT '{}');
CREATE INDEX IF NOT EXISTS idx_runs_rule_time ON automation_runs(rule_id, timestamp DESC);
CREATE TABLE IF NOT EXISTS profiles (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, updated_at REAL NOT NULL, name TEXT NOT NULL UNIQUE, profile_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_profiles_updated ON profiles(updated_at DESC);
CREATE TABLE IF NOT EXISTS firewall_rules (id INTEGER PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, updated_at REAL NOT NULL, bundle_id TEXT, target TEXT NOT NULL, mode TEXT NOT NULL, expires_at REAL, profile_id INTEGER);
CREATE INDEX IF NOT EXISTS idx_firewall_bundle_target ON firewall_rules(bundle_id, target);
CREATE TABLE IF NOT EXISTS frozen_apps (bundle_id TEXT PRIMARY KEY, schema_version INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL, updated_at REAL NOT NULL, state TEXT NOT NULL, original_state_json TEXT NOT NULL, expires_at REAL);
CREATE INDEX IF NOT EXISTS idx_frozen_state ON frozen_apps(state, updated_at DESC);
"""

MIGRATION_3 = """
CREATE INDEX IF NOT EXISTS idx_process_time ON process_samples(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_process_name_time ON process_samples(process, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_battery_source_time ON battery_samples(source, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_thermal_state_time ON thermal_samples(state, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_health_time ON health_samples(timestamp DESC);
CREATE TABLE IF NOT EXISTS telemetry_rollups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  window_seconds INTEGER NOT NULL,
  metric TEXT NOT NULL,
  subject TEXT NOT NULL,
  value_real REAL,
  sample_count INTEGER NOT NULL,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rollup_window_metric_subject
ON telemetry_rollups(created_at, window_seconds, metric, subject);
CREATE INDEX IF NOT EXISTS idx_rollup_metric_time
ON telemetry_rollups(metric, created_at DESC);
"""

MIGRATION_4 = """
CREATE TABLE IF NOT EXISTS network_snapshots (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  timestamp REAL NOT NULL UNIQUE,
  connection_count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_network_snapshots_time ON network_snapshots(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_time ON network_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_destination_time ON network_events(destination, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_decision_time ON network_events(decision, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_privacy_time ON privacy_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_privacy_bundle_time ON privacy_events(bundle_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_privacy_decision_time ON privacy_events(decision, timestamp DESC);
"""

MIGRATION_5 = """
ALTER TABLE crashes ADD COLUMN fingerprint TEXT;
ALTER TABLE crashes ADD COLUMN kind TEXT NOT NULL DEFAULT 'crash';
ALTER TABLE crashes ADD COLUMN incident_id TEXT;
ALTER TABLE crashes ADD COLUMN signal TEXT;
ALTER TABLE crashes ADD COLUMN reason TEXT;
ALTER TABLE crashes ADD COLUMN package_candidates_json TEXT NOT NULL DEFAULT '[]';
CREATE UNIQUE INDEX IF NOT EXISTS idx_crashes_fingerprint ON crashes(fingerprint);
CREATE INDEX IF NOT EXISTS idx_crashes_kind_time ON crashes(kind, timestamp DESC);
ALTER TABLE tweak_hooks ADD COLUMN fingerprint TEXT;
ALTER TABLE tweak_hooks ADD COLUMN class_name TEXT;
ALTER TABLE tweak_hooks ADD COLUMN library TEXT;
ALTER TABLE tweak_hooks ADD COLUMN mechanism TEXT;
ALTER TABLE tweak_hooks ADD COLUMN implementation TEXT;
ALTER TABLE tweak_hooks ADD COLUMN active INTEGER NOT NULL DEFAULT 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_tweak_hooks_fingerprint ON tweak_hooks(fingerprint);
CREATE INDEX IF NOT EXISTS idx_tweak_hooks_active_process ON tweak_hooks(active, process, symbol);
ALTER TABLE conflicts ADD COLUMN fingerprint TEXT;
ALTER TABLE conflicts ADD COLUMN process TEXT;
ALTER TABLE conflicts ADD COLUMN active INTEGER NOT NULL DEFAULT 1;
CREATE UNIQUE INDEX IF NOT EXISTS idx_conflicts_fingerprint ON conflicts(fingerprint);
CREATE INDEX IF NOT EXISTS idx_conflicts_active_severity ON conflicts(active, severity, updated_at DESC);
CREATE TABLE IF NOT EXISTS safe_mode_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  process TEXT NOT NULL,
  crash_count INTEGER NOT NULL,
  state TEXT NOT NULL,
  action TEXT,
  evidence_json TEXT NOT NULL DEFAULT '{}',
  result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_safe_mode_process_time
ON safe_mode_sessions(process, updated_at DESC);
"""

MIGRATION_6 = """
ALTER TABLE app_snapshots ADD COLUMN metadata_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE app_snapshots ADD COLUMN bundle_path TEXT;
ALTER TABLE app_snapshots ADD COLUMN container_path TEXT;
ALTER TABLE app_snapshots ADD COLUMN file_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE app_snapshots ADD COLUMN state_digest TEXT;
ALTER TABLE app_snapshots ADD COLUMN purpose TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE app_snapshots ADD COLUMN parent_snapshot_id INTEGER;
ALTER TABLE app_snapshots ADD COLUMN verified_at REAL;
ALTER TABLE app_snapshots ADD COLUMN deleted_at REAL;
CREATE INDEX IF NOT EXISTS idx_snapshots_state_time
ON app_snapshots(state, created_at DESC);
ALTER TABLE changes ADD COLUMN undo_operation TEXT;
ALTER TABLE changes ADD COLUMN undo_parameters_json TEXT;
ALTER TABLE changes ADD COLUMN undone_at REAL;
ALTER TABLE changes ADD COLUMN result_json TEXT;
CREATE INDEX IF NOT EXISTS idx_changes_reversible_time
ON changes(reversible, undone_at, timestamp DESC);
"""

MIGRATION_7 = """
ALTER TABLE profiles ADD COLUMN built_in INTEGER NOT NULL DEFAULT 0;
ALTER TABLE profiles ADD COLUMN active INTEGER NOT NULL DEFAULT 0;
ALTER TABLE profiles ADD COLUMN last_applied_at REAL;
ALTER TABLE profiles ADD COLUMN status TEXT NOT NULL DEFAULT 'Ready';
ALTER TABLE profiles ADD COLUMN last_error TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_profiles_single_active
ON profiles(active) WHERE active=1;
ALTER TABLE automation_rules ADD COLUMN last_error TEXT;
ALTER TABLE automation_rules ADD COLUMN last_run_at REAL;
ALTER TABLE automation_rules ADD COLUMN run_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE frozen_apps ADD COLUMN applied_controls_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE frozen_apps ADD COLUMN last_error TEXT;
ALTER TABLE frozen_apps ADD COLUMN profile_name TEXT;
CREATE TABLE IF NOT EXISTS profile_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  completed_at REAL,
  profile_name TEXT NOT NULL,
  previous_profile_name TEXT,
  state TEXT NOT NULL,
  previous_state_json TEXT NOT NULL DEFAULT '{}',
  requested_state_json TEXT NOT NULL DEFAULT '{}',
  effective_state_json TEXT NOT NULL DEFAULT '{}',
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_profile_transactions_time
ON profile_transactions(created_at DESC);
CREATE TABLE IF NOT EXISTS automation_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  timestamp REAL NOT NULL,
  trigger_type TEXT NOT NULL,
  subject TEXT,
  event_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_automation_events_time
ON automation_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_automation_events_trigger_time
ON automation_events(trigger_type, timestamp DESC);
"""

MIGRATION_8 = """
CREATE TABLE IF NOT EXISTS notification_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  timestamp REAL NOT NULL,
  bundle_id TEXT NOT NULL,
  category_id TEXT,
  source TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  metadata_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_notification_time
ON notification_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_notification_bundle_time
ON notification_events(bundle_id,timestamp DESC);
CREATE TABLE IF NOT EXISTS permission_timeouts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  schema_version INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  bundle_id TEXT NOT NULL,
  resource TEXT NOT NULL,
  requested_policy TEXT NOT NULL,
  previous_policy TEXT NOT NULL,
  duration TEXT NOT NULL,
  expires_at REAL,
  expiration_condition TEXT,
  state TEXT NOT NULL,
  provider TEXT,
  last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_permission_active_expiry
ON permission_timeouts(state,expires_at);
CREATE INDEX IF NOT EXISTS idx_permission_bundle_resource
ON permission_timeouts(bundle_id,resource,updated_at DESC);
"""

MIGRATIONS = {1: MIGRATION_1, 2: MIGRATION_2, 3: MIGRATION_3, 4: MIGRATION_4,
              5: MIGRATION_5, 6: MIGRATION_6, 7: MIGRATION_7, 8: MIGRATION_8}
RETENTION_TABLES = {
    "events": "timestamp", "network_events": "timestamp", "privacy_events": "timestamp",
    "process_samples": "timestamp", "battery_samples": "timestamp",
    "thermal_samples": "timestamp", "health_samples": "timestamp",
    "automation_runs": "timestamp", "automation_events": "timestamp",
    "notification_events": "timestamp",
    "network_snapshots": "timestamp",
    "crashes": "timestamp",
}


class EventStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self.recovery_copy: Path | None = None

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None,
                                     check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        return connection

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("event store is not initialized")
        return self._connection

    def initialize(self) -> None:
        with self._lock:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            existed = self.path.exists()
            try:
                connection = self._connect()
                result = connection.execute("PRAGMA quick_check(1)").fetchone()[0]
                if result != "ok":
                    raise sqlite3.DatabaseError(f"integrity check failed: {result}")
                self._connection = connection
            except sqlite3.DatabaseError:
                try:
                    connection.close()
                except Exception:
                    pass
                if not existed:
                    raise
                stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                recovery = self.path.with_name(self.path.name + f".corrupt.{stamp}")
                os.replace(self.path, recovery)
                for suffix in ("-wal", "-shm"):
                    sidecar = Path(str(self.path) + suffix)
                    if sidecar.exists():
                        # Preserve the sidecar with the corrupt database while
                        # ensuring SQLite cannot attach stale WAL pages to the
                        # new empty database at the canonical path.
                        os.replace(sidecar, Path(str(recovery) + suffix))
                self.recovery_copy = recovery
                self._connection = self._connect()
            self._migrate()
            if self.recovery_copy:
                self.record_event("RECOVERY", "DATABASE_RECOVERED", "WARN",
                                  {"preserved": str(self.recovery_copy)})

    def close(self) -> None:
        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None

    def _migrate(self) -> None:
        connection = self.connection
        current = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if current > SCHEMA_VERSION:
            raise RuntimeError("database schema is newer than this runtime")
        for version in range(current + 1, SCHEMA_VERSION + 1):
            script = MIGRATIONS[version]
            connection.executescript("BEGIN IMMEDIATE;\n" + script +
                                      f"\nPRAGMA user_version={version};\nCOMMIT;")
            connection.execute("INSERT OR REPLACE INTO schema_migrations(version,applied_at) VALUES(?,?)",
                               (version, time.time()))

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))

    def record_event(self, component: str, event_type: str, severity: str,
                     payload: Any, timestamp: float | None = None) -> int:
        with self._lock:
            cursor = self.connection.execute(
                "INSERT INTO events(timestamp,component,event_type,severity,payload_json) VALUES(?,?,?,?,?)",
                (time.time() if timestamp is None else timestamp, component, event_type,
                 severity, self._json(payload)))
            return int(cursor.lastrowid)

    def record_change(self, component: str, action: str, target: str,
                      previous_state: Any = None, new_state: Any = None,
                      reversible: bool = False, transaction_id: str | None = None,
                      undo_operation: str | None = None,
                      undo_parameters: Any = None, result: Any = None) -> int:
        with self._lock:
            cursor = self.connection.execute(
                """INSERT INTO changes(
                     timestamp,component,action,target,previous_state_json,
                     new_state_json,reversible,transaction_id,undo_operation,
                     undo_parameters_json,result_json)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (time.time(), component, action, target,
                 None if previous_state is None else self._json(previous_state),
                 None if new_state is None else self._json(new_state),
                 1 if reversible else 0, transaction_id, undo_operation,
                 None if undo_parameters is None else self._json(undo_parameters),
                 None if result is None else self._json(result)))
            return int(cursor.lastrowid)

    def record_app_snapshot(self, *, bundle_id: str, app_version: str,
                            manifest_path: str, total_size: int,
                            manifest_sha256: str, file_count: int,
                            state_digest: str, container_path: str,
                            bundle_path: str, purpose: str,
                            parent_snapshot_id: int | None = None,
                            timestamp: float | None = None) -> int:
        stamp = time.time() if timestamp is None else float(timestamp)
        with self._lock:
            cursor = self.connection.execute("""
              INSERT INTO app_snapshots(
                created_at,updated_at,bundle_id,app_version,manifest_path,
                total_size,manifest_sha256,state,metadata_version,bundle_path,
                container_path,file_count,state_digest,purpose,parent_snapshot_id)
              VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (stamp, stamp, str(bundle_id)[:255], str(app_version)[:128],
                  str(manifest_path)[:4096], max(0, int(total_size)),
                  str(manifest_sha256)[:64], "ready", 1,
                  str(bundle_path)[:4096], str(container_path)[:4096],
                  max(0, int(file_count)), str(state_digest)[:64],
                  str(purpose)[:64], parent_snapshot_id))
            return int(cursor.lastrowid)

    def app_snapshot(self, snapshot_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM app_snapshots WHERE id=?", (int(snapshot_id),)).fetchone()
        return dict(row) if row else None

    def list_app_snapshots(self, bundle_id: str | None = None,
                           limit: int = 100) -> list[dict[str, Any]]:
        count = min(500, max(1, int(limit)))
        with self._lock:
            if bundle_id:
                rows = self.connection.execute("""
                  SELECT * FROM app_snapshots
                  WHERE state!='deleted' AND bundle_id=?
                  ORDER BY created_at DESC,id DESC LIMIT ?
                """, (str(bundle_id)[:255], count)).fetchall()
            else:
                rows = self.connection.execute("""
                  SELECT * FROM app_snapshots WHERE state!='deleted'
                  ORDER BY created_at DESC,id DESC LIMIT ?
                """, (count,)).fetchall()
        return [dict(row) for row in rows]

    def mark_snapshot_verified(self, snapshot_id: int,
                               timestamp: float | None = None) -> None:
        stamp = time.time() if timestamp is None else float(timestamp)
        with self._lock:
            self.connection.execute("""
              UPDATE app_snapshots SET verified_at=?,updated_at=?
              WHERE id=? AND state!='deleted'
            """, (stamp, stamp, int(snapshot_id)))

    def mark_snapshot_deleted(self, snapshot_id: int,
                              timestamp: float | None = None) -> None:
        stamp = time.time() if timestamp is None else float(timestamp)
        with self._lock:
            cursor = self.connection.execute("""
              UPDATE app_snapshots SET state='deleted',deleted_at=?,updated_at=?
              WHERE id=? AND state!='deleted'
            """, (stamp, stamp, int(snapshot_id)))
            if cursor.rowcount != 1:
                raise ValueError("snapshot does not exist or was already deleted")

    def record_process_samples(self, samples: Iterable[dict[str, Any]],
                               timestamp: float | None = None) -> int:
        """Insert one bounded process snapshot in a single transaction."""
        rows = list(samples)[:1024]
        if not rows:
            return 0
        stamp = time.time() if timestamp is None else float(timestamp)
        values = [(stamp, int(row["pid"]), row.get("ppid"), row.get("uid"),
                   str(row.get("process") or "")[:512],
                   str(row.get("executable") or "")[:4096], row.get("cpu"),
                   row.get("memory_bytes"), row.get("wakeups"),
                   self._json(row.get("metadata") or {})) for row in rows]
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.executemany("""
                  INSERT INTO process_samples(timestamp,pid,ppid,uid,process,executable,cpu,memory_bytes,wakeups,metadata_json)
                  VALUES(?,?,?,?,?,?,?,?,?,?)
                """, values)
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
        return len(values)

    def record_battery_sample(self, sample: dict[str, Any],
                              timestamp: float | None = None) -> int:
        with self._lock:
            cursor = self.connection.execute("""
              INSERT INTO battery_samples(timestamp,level,charging,source,metadata_json)
              VALUES(?,?,?,?,?)
            """, (time.time() if timestamp is None else float(timestamp),
                  sample.get("level"), 1 if sample.get("charging") else 0,
                  str(sample.get("source") or "unknown")[:128],
                  self._json(sample.get("metadata") or {})))
            return int(cursor.lastrowid)

    def record_thermal_sample(self, sample: dict[str, Any],
                              timestamp: float | None = None) -> int:
        with self._lock:
            cursor = self.connection.execute("""
              INSERT INTO thermal_samples(timestamp,state,source,metadata_json)
              VALUES(?,?,?,?)
            """, (time.time() if timestamp is None else float(timestamp),
                  str(sample["state"]), str(sample.get("source") or "unknown")[:128],
                  self._json(sample.get("metadata") or {})))
            return int(cursor.lastrowid)

    def record_health_samples(self, samples: Iterable[dict[str, Any]],
                              timestamp: float | None = None) -> int:
        rows = list(samples)[:128]
        if not rows:
            return 0
        stamp = time.time() if timestamp is None else float(timestamp)
        values = [(stamp, str(row["metric"])[:128], row.get("value_real"),
                   None if row.get("value_text") is None else str(row["value_text"])[:2048],
                   self._json(row.get("metadata") or {})) for row in rows]
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.executemany("""
                  INSERT INTO health_samples(timestamp,metric,value_real,value_text,metadata_json)
                  VALUES(?,?,?,?,?)
                """, values)
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
        return len(values)

    def record_network_events(self, samples: Iterable[dict[str, Any]],
                              timestamp: float | None = None) -> int:
        rows = list(samples)[:2048]
        stamp = time.time() if timestamp is None else float(timestamp)
        values = [(float(row.get("timestamp", stamp)), row.get("bundle_id"),
                   row.get("pid"), str(row.get("destination") or "")[:1024],
                   str(row.get("protocol") or "")[:32], row.get("port"),
                   row.get("bytes_sent"), row.get("bytes_received"),
                   str(row.get("decision") or "Observed")[:64],
                   self._json(row.get("metadata") or {})) for row in rows]
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.execute(
                    "INSERT INTO network_snapshots(timestamp,connection_count) VALUES(?,?)",
                    (stamp, len(values)))
                self.connection.executemany("""
                  INSERT INTO network_events(timestamp,bundle_id,pid,destination,protocol,port,bytes_sent,bytes_received,decision,metadata_json)
                  VALUES(?,?,?,?,?,?,?,?,?,?)
                """, values)
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
        return len(values)

    def record_privacy_events(self, samples: Iterable[dict[str, Any]]) -> int:
        rows = list(samples)[:512]
        if not rows:
            return 0
        values = [(float(row["timestamp"]), row.get("bundle_id"), row.get("pid"),
                   str(row["resource"])[:64], str(row.get("action") or "access")[:128],
                   str(row.get("decision") or "Observed")[:64],
                   self._json(row.get("metadata") or {})) for row in rows]
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.executemany("""
                  INSERT INTO privacy_events(timestamp,bundle_id,pid,resource,action,decision,metadata_json)
                  VALUES(?,?,?,?,?,?,?)
                """, values)
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
        return len(values)

    def record_crashes(self, samples: Iterable[dict[str, Any]]) -> int:
        """Insert new crash metadata without copying report contents."""
        rows = list(samples)[:512]
        if not rows:
            return 0
        values = [(str(row["fingerprint"]), float(row["timestamp"]),
                   str(row["process"])[:512], row.get("bundle_id"),
                   str(row["report_path"])[:4096],
                   str(row.get("kind") or "crash")[:64], row.get("incident_id"),
                   row.get("signal"), row.get("reason"),
                   self._json(row.get("package_candidates") or []),
                   self._json(row.get("evidence") or {})) for row in rows]
        with self._lock:
            before = self.connection.total_changes
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.executemany("""
                  INSERT OR IGNORE INTO crashes(
                    fingerprint,timestamp,process,bundle_id,report_path,kind,
                    incident_id,signal,reason,package_candidates_json,evidence_json)
                  VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """, values)
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
            return self.connection.total_changes - before

    def replace_hook_conflicts(self, samples: Iterable[dict[str, Any]],
                               timestamp: float | None = None) -> tuple[int, int]:
        """Refresh current evidence while retaining inactive history."""
        rows = list(samples)[:4096]
        stamp = time.time() if timestamp is None else float(timestamp)
        hooks = [row for row in rows if row.get("kind") == "hook"]
        conflicts = [row for row in rows if row.get("kind") == "conflict"]
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.execute("UPDATE tweak_hooks SET active=0")
                self.connection.execute("UPDATE conflicts SET active=0")
                for row in hooks:
                    self.connection.execute("""
                      INSERT INTO tweak_hooks(
                        fingerprint,created_at,updated_at,process,image,library,
                        class_name,symbol,implementation,mechanism,package,evidence_json,active)
                      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,1)
                      ON CONFLICT(fingerprint) DO UPDATE SET
                        updated_at=excluded.updated_at,evidence_json=excluded.evidence_json,active=1
                    """, (str(row["fingerprint"]), stamp, stamp,
                          str(row.get("process") or "")[:512], row.get("image"),
                          row.get("library"), row.get("class_name"), row.get("symbol"),
                          row.get("implementation"), row.get("mechanism"),
                          row.get("package"), self._json(row.get("evidence") or {})))
                for row in conflicts:
                    evidence = dict(row.get("evidence") or {})
                    evidence["providers"] = list(row.get("providers") or [])
                    self.connection.execute("""
                      INSERT INTO conflicts(
                        fingerprint,created_at,updated_at,severity,target,process,evidence_json,active)
                      VALUES(?,?,?,?,?,?,?,1)
                      ON CONFLICT(fingerprint) DO UPDATE SET
                        updated_at=excluded.updated_at,severity=excluded.severity,
                        evidence_json=excluded.evidence_json,active=1
                    """, (str(row["fingerprint"]), stamp, stamp,
                          str(row.get("classification") or "informational")[:64],
                          str(row.get("target") or "")[:4096],
                          str(row.get("process") or "")[:512], self._json(evidence)))
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
        return len(hooks), len(conflicts)

    def latest_crashes(self, limit: int = 100, process: str | None = None) -> list[dict[str, Any]]:
        count = min(500, max(1, int(limit)))
        with self._lock:
            if process:
                rows = self.connection.execute("""
                  SELECT * FROM crashes WHERE process=?
                  ORDER BY timestamp DESC,id DESC LIMIT ?
                """, (str(process)[:512], count)).fetchall()
            else:
                rows = self.connection.execute(
                    "SELECT * FROM crashes ORDER BY timestamp DESC,id DESC LIMIT ?", (count,)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["evidence"] = json.loads(value.pop("evidence_json") or "{}")
            value["package_candidates"] = json.loads(
                value.pop("package_candidates_json") or "[]")
            result.append(value)
        return result

    def current_conflicts(self, limit: int = 200) -> list[dict[str, Any]]:
        count = min(500, max(1, int(limit)))
        with self._lock:
            rows = self.connection.execute("""
              SELECT * FROM conflicts WHERE active=1
              ORDER BY CASE severity WHEN 'probable conflict' THEN 0
                                     WHEN 'possible conflict' THEN 1 ELSE 2 END,
                       updated_at DESC,id DESC LIMIT ?
            """, (count,)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["active"] = bool(value["active"])
            value["evidence"] = json.loads(value.pop("evidence_json") or "{}")
            result.append(value)
        return result

    def current_hooks(self, limit: int = 500) -> list[dict[str, Any]]:
        count = min(1000, max(1, int(limit)))
        with self._lock:
            rows = self.connection.execute("""
              SELECT * FROM tweak_hooks WHERE active=1
              ORDER BY process,symbol,package LIMIT ?
            """, (count,)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["active"] = bool(value["active"])
            value["evidence"] = json.loads(value.pop("evidence_json") or "{}")
            result.append(value)
        return result

    def package_health(self, since: float) -> dict[str, dict[str, int]]:
        """Derive counts without treating the cache as package truth."""
        result: dict[str, dict[str, int]] = {}
        for crash in self.latest_crashes(500):
            if float(crash["timestamp"]) < float(since):
                continue
            for package in crash["package_candidates"]:
                result.setdefault(str(package), {"crashes": 0, "conflicts": 0})["crashes"] += 1
        for conflict in self.current_conflicts(500):
            if conflict["severity"] == "informational":
                continue
            for package in conflict["evidence"].get("providers", []):
                result.setdefault(str(package), {"crashes": 0, "conflicts": 0})["conflicts"] += 1
        return result

    def record_safe_mode_session(self, process: str, crash_count: int,
                                 state: str, action: str | None,
                                 evidence: Any, result: Any = None,
                                 timestamp: float | None = None) -> int:
        stamp = time.time() if timestamp is None else float(timestamp)
        with self._lock:
            cursor = self.connection.execute("""
              INSERT INTO safe_mode_sessions(
                created_at,updated_at,process,crash_count,state,action,evidence_json,result_json)
              VALUES(?,?,?,?,?,?,?,?)
            """, (stamp, stamp, str(process)[:512], max(0, int(crash_count)),
                  str(state)[:64], str(action)[:128] if action else None,
                  self._json(evidence or {}),
                  None if result is None else self._json(result)))
            return int(cursor.lastrowid)

    def latest_safe_mode_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        count = min(200, max(1, int(limit)))
        with self._lock:
            rows = self.connection.execute("""
              SELECT * FROM safe_mode_sessions
              ORDER BY updated_at DESC,id DESC LIMIT ?
            """, (count,)).fetchall()
        answer = []
        for row in rows:
            value = dict(row)
            value["evidence"] = json.loads(value.pop("evidence_json") or "{}")
            raw_result = value.pop("result_json")
            value["result"] = json.loads(raw_result) if raw_result else None
            answer.append(value)
        return answer

    def latest_rows(self, table: str, limit: int = 100) -> list[dict[str, Any]]:
        allowed = {"process_samples", "battery_samples", "thermal_samples",
                   "health_samples", "network_events", "privacy_events"}
        if table not in allowed:
            raise ValueError("table is not telemetry-readable")
        count = min(1000, max(1, int(limit)))
        with self._lock:
            rows = self.connection.execute(
                f"SELECT * FROM {table} ORDER BY timestamp DESC, id DESC LIMIT ?",
                (count,)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            if "metadata_json" in value:
                value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
            if "charging" in value:
                value["charging"] = bool(value["charging"])
            result.append(value)
        return result

    def latest_network_snapshot(self, limit: int = 512) -> list[dict[str, Any]]:
        count = min(1024, max(1, int(limit)))
        with self._lock:
            stamp = self.connection.execute(
                "SELECT MAX(timestamp) FROM network_snapshots").fetchone()[0]
            if stamp is None:
                return []
            rows = self.connection.execute("""
              SELECT * FROM network_events WHERE timestamp=?
              ORDER BY bundle_id, destination, port LIMIT ?
            """, (stamp, count)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
            result.append(value)
        return result

    def privacy_summary(self, since: float) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute("""
              SELECT resource, COUNT(*) AS count, MAX(timestamp) AS latest
              FROM privacy_events WHERE timestamp>=?
              GROUP BY resource ORDER BY count DESC, resource
            """, (float(since),)).fetchall()
        return [dict(row) for row in rows]

    def latest_timestamp(self, table: str) -> float | None:
        if table not in {"network_events", "network_snapshots", "privacy_events"}:
            raise ValueError("table is not activity-readable")
        with self._lock:
            value = self.connection.execute(
                f"SELECT MAX(timestamp) FROM {table}").fetchone()[0]
        return None if value is None else float(value)

    def latest_process_snapshot(self, limit: int = 512) -> list[dict[str, Any]]:
        count = min(1024, max(1, int(limit)))
        with self._lock:
            stamp = self.connection.execute(
                "SELECT MAX(timestamp) FROM process_samples").fetchone()[0]
            if stamp is None:
                return []
            rows = self.connection.execute("""
              SELECT * FROM process_samples WHERE timestamp=?
              ORDER BY cpu DESC, memory_bytes DESC, pid ASC LIMIT ?
            """, (stamp, count)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
            result.append(value)
        return result

    def latest_health_metrics(self) -> list[dict[str, Any]]:
        """Return one newest value per metric without an unbounded scan."""
        with self._lock:
            rows = self.connection.execute("""
              SELECT h.* FROM health_samples h
              JOIN (SELECT metric, MAX(id) AS newest FROM health_samples GROUP BY metric) x
                ON h.id=x.newest
              ORDER BY h.metric LIMIT 256
            """).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
            result.append(value)
        return result

    def health_timeline(self, since: float, sample_limit: int = 240) -> dict[str, Any]:
        """Return a bounded, aggregate-first device-health history.

        The summary queries use indexed timestamps and the returned raw metric
        points are capped.  This keeps the 30-day view useful without sending
        every five-minute sample over IPC.
        """
        cutoff = float(since)
        count = min(500, max(1, int(sample_limit)))
        with self._lock:
            health = self.connection.execute("""
              SELECT * FROM health_samples WHERE timestamp>=?
              ORDER BY timestamp DESC,id DESC LIMIT ?
            """, (cutoff, count)).fetchall()
            crash = self.connection.execute("""
              SELECT COUNT(*) AS total,
                     SUM(CASE WHEN lower(process) IN ('springboard','com.apple.springboard')
                              THEN 1 ELSE 0 END) AS springboard
              FROM crashes WHERE timestamp>=?
            """, (cutoff,)).fetchone()
            thermal = self.connection.execute("""
              SELECT state,COUNT(*) AS count FROM thermal_samples
              WHERE timestamp>=? GROUP BY state ORDER BY count DESC,state
            """, (cutoff,)).fetchall()
            battery = self.connection.execute("""
              SELECT COUNT(*) AS count,AVG(level) AS average_level,
                     MIN(level) AS minimum_level,MAX(level) AS maximum_level
              FROM battery_samples WHERE timestamp>=?
            """, (cutoff,)).fetchone()
        samples = []
        for row in health:
            value = dict(row)
            value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
            samples.append(value)
        return {
            "since": cutoff,
            "generatedAt": time.time(),
            "healthSamples": samples,
            "healthSamplesTruncated": len(samples) == count,
            "crashes": {"total": int(crash["total"] or 0),
                        "springboard": int(crash["springboard"] or 0)},
            "thermalEvents": [{"state": str(row["state"]),
                               "count": int(row["count"])} for row in thermal],
            "battery": {"sampleCount": int(battery["count"] or 0),
                        "averageLevel": battery["average_level"],
                        "minimumLevel": battery["minimum_level"],
                        "maximumLevel": battery["maximum_level"]},
        }

    def recent_changes(self, limit: int = 50) -> list[dict[str, Any]]:
        limit = min(200, max(1, int(limit)))
        with self._lock:
            rows = self.connection.execute(
                "SELECT * FROM changes ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            for key in ("previous_state_json", "new_state_json",
                        "undo_parameters_json", "result_json"):
                raw = value.pop(key)
                value[key.removesuffix("_json")] = json.loads(raw) if raw else None
            value["reversible"] = bool(value["reversible"])
            result.append(value)
        return result

    def change(self, change_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM changes WHERE id=?", (int(change_id),)).fetchone()
        if row is None:
            return None
        value = dict(row)
        for key in ("previous_state_json", "new_state_json",
                    "undo_parameters_json", "result_json"):
            raw = value.pop(key)
            value[key.removesuffix("_json")] = json.loads(raw) if raw else None
        value["reversible"] = bool(value["reversible"])
        return value

    def mark_change_undone(self, change_id: int, result: Any,
                           timestamp: float | None = None) -> None:
        stamp = time.time() if timestamp is None else float(timestamp)
        with self._lock:
            cursor = self.connection.execute("""
              UPDATE changes SET undone_at=?,result_json=?
              WHERE id=? AND reversible=1 AND undone_at IS NULL
            """, (stamp, self._json(result), int(change_id)))
            if cursor.rowcount != 1:
                raise ValueError("change is not eligible for undo")

    # Phase 6 policy storage.  Every JSON column is decoded at this boundary so
    # callers never need to depend on SQLite's physical representation.
    def upsert_profile(self, name: str, profile: Any, built_in: bool = False) -> int:
        now = time.time()
        with self._lock:
            self.connection.execute("""
              INSERT INTO profiles(created_at,updated_at,name,profile_json,built_in)
              VALUES(?,?,?,?,?)
              ON CONFLICT(name) DO UPDATE SET
                updated_at=excluded.updated_at,
                profile_json=CASE WHEN profiles.built_in=1 AND excluded.built_in=0
                                  THEN profiles.profile_json ELSE excluded.profile_json END,
                built_in=MAX(profiles.built_in,excluded.built_in)
            """, (now, now, str(name)[:80], self._json(profile), 1 if built_in else 0))
            row = self.connection.execute("SELECT id FROM profiles WHERE name=?", (name,)).fetchone()
            return int(row[0])

    @staticmethod
    def _profile_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = dict(row)
        value["profile"] = json.loads(value.pop("profile_json") or "{}")
        value["built_in"] = bool(value["built_in"])
        value["active"] = bool(value["active"])
        return value

    def profile(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute("SELECT * FROM profiles WHERE name=?", (name,)).fetchone()
        return self._profile_row(row)

    def profiles(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT * FROM profiles ORDER BY active DESC,built_in DESC,name COLLATE NOCASE").fetchall()
        return [value for row in rows if (value := self._profile_row(row)) is not None]

    def active_profile(self) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute("SELECT * FROM profiles WHERE active=1 LIMIT 1").fetchone()
            raw = self.connection.execute("SELECT value FROM metadata WHERE key='active_profile_effective'").fetchone()
        value = self._profile_row(row)
        if value is not None:
            value["effective_state"] = json.loads(raw[0]) if raw else {}
        return value

    def set_active_profile(self, name: str, effective_state: Any) -> None:
        now = time.time()
        with self._lock:
            if not self.connection.execute("SELECT 1 FROM profiles WHERE name=?", (name,)).fetchone():
                raise ValueError("profile does not exist")
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.execute("UPDATE profiles SET active=0")
                self.connection.execute(
                    "UPDATE profiles SET active=1,last_applied_at=?,status='Ready',last_error=NULL WHERE name=?",
                    (now, name))
                self.connection.execute("""
                  INSERT INTO metadata(key,value,schema_version,created_at,updated_at)
                  VALUES('active_profile_effective',?,1,?,?)
                  ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at
                """, (self._json(effective_state), now, now))
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise

    def begin_profile_transaction(self, profile_name: str,
                                  previous_profile_name: str | None,
                                  previous_state: Any, requested_state: Any) -> int:
        with self._lock:
            cursor = self.connection.execute("""
              INSERT INTO profile_transactions(
                created_at,profile_name,previous_profile_name,state,
                previous_state_json,requested_state_json)
              VALUES(?,?,?,'Applying',?,?)
            """, (time.time(), profile_name, previous_profile_name,
                  self._json(previous_state), self._json(requested_state)))
            return int(cursor.lastrowid)

    def finish_profile_transaction(self, transaction_id: int, state: str,
                                   effective_state: Any, error: str | None = None) -> None:
        if state not in {"Committed", "RolledBack"}:
            raise ValueError("invalid transaction state")
        with self._lock:
            self.connection.execute("""
              UPDATE profile_transactions SET completed_at=?,state=?,effective_state_json=?,error=?
              WHERE id=? AND state='Applying'
            """, (time.time(), state, self._json(effective_state),
                  None if error is None else str(error)[:2048], int(transaction_id)))

    def profile_transactions(self, limit: int = 100) -> list[dict[str, Any]]:
        count = min(500, max(1, int(limit)))
        with self._lock:
            rows = self.connection.execute(
                "SELECT * FROM profile_transactions ORDER BY created_at DESC,id DESC LIMIT ?",
                (count,)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            for key in ("previous_state_json", "requested_state_json", "effective_state_json"):
                value[key.removesuffix("_json")] = json.loads(value.pop(key) or "{}")
            result.append(value)
        return result

    def upsert_automation_rule(self, name: str, rule: Any, enabled: bool,
                               rule_id: int | None = None) -> int:
        now = time.time()
        with self._lock:
            if rule_id is None:
                cursor = self.connection.execute("""
                  INSERT INTO automation_rules(created_at,updated_at,name,enabled,rule_json)
                  VALUES(?,?,?,?,?)
                """, (now, now, str(name)[:80], 1 if enabled else 0, self._json(rule)))
                return int(cursor.lastrowid)
            cursor = self.connection.execute("""
              UPDATE automation_rules SET updated_at=?,name=?,enabled=?,rule_json=?,last_error=NULL
              WHERE id=?
            """, (now, str(name)[:80], 1 if enabled else 0,
                  self._json(rule), int(rule_id)))
            if cursor.rowcount != 1:
                raise ValueError("automation rule does not exist")
            return int(rule_id)

    @staticmethod
    def _rule_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = dict(row)
        value["rule"] = json.loads(value.pop("rule_json") or "{}")
        value["enabled"] = bool(value["enabled"])
        return value

    def automation_rule(self, rule_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM automation_rules WHERE id=?", (int(rule_id),)).fetchone()
        return self._rule_row(row)

    def automation_rules(self, enabled_only: bool = False,
                         limit: int = 500) -> list[dict[str, Any]]:
        count = min(1000, max(1, int(limit)))
        query = "SELECT * FROM automation_rules"
        if enabled_only:
            query += " WHERE enabled=1"
        query += " ORDER BY updated_at DESC,id DESC LIMIT ?"
        with self._lock:
            rows = self.connection.execute(query, (count,)).fetchall()
        return [value for row in rows if (value := self._rule_row(row)) is not None]

    def set_rule_enabled(self, rule_id: int, enabled: bool) -> None:
        with self._lock:
            cursor = self.connection.execute(
                "UPDATE automation_rules SET enabled=?,updated_at=? WHERE id=?",
                (1 if enabled else 0, time.time(), int(rule_id)))
            if cursor.rowcount != 1:
                raise ValueError("automation rule does not exist")

    def record_automation_run(self, rule_id: int, success: bool, result: Any,
                              error: str | None = None) -> int:
        now = time.time()
        with self._lock:
            cursor = self.connection.execute(
                "INSERT INTO automation_runs(timestamp,rule_id,success,result_json) VALUES(?,?,?,?)",
                (now, int(rule_id), 1 if success else 0, self._json(result)))
            self.connection.execute("""
              UPDATE automation_rules SET last_run_at=?,run_count=run_count+1,last_error=? WHERE id=?
            """, (now, None if error is None else str(error)[:2048], int(rule_id)))
            return int(cursor.lastrowid)

    def automation_runs(self, limit: int = 100) -> list[dict[str, Any]]:
        count = min(500, max(1, int(limit)))
        with self._lock:
            rows = self.connection.execute(
                "SELECT * FROM automation_runs ORDER BY timestamp DESC,id DESC LIMIT ?",
                (count,)).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["success"] = bool(value["success"])
            value["result"] = json.loads(value.pop("result_json") or "{}")
            result.append(value)
        return result

    def record_automation_event(self, trigger_type: str, subject: str | None,
                                event: Any) -> int:
        with self._lock:
            cursor = self.connection.execute("""
              INSERT INTO automation_events(timestamp,trigger_type,subject,event_json)
              VALUES(?,?,?,?)
            """, (time.time(), str(trigger_type)[:64],
                  None if subject is None else str(subject)[:255], self._json(event)))
            return int(cursor.lastrowid)

    def frozen_app(self, bundle_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT * FROM frozen_apps WHERE bundle_id=?", (bundle_id,)).fetchone()
        return self._frozen_row(row)

    @staticmethod
    def _frozen_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if row is None:
            return None
        value = dict(row)
        value["original_state"] = json.loads(value.pop("original_state_json") or "{}")
        value["applied_controls"] = json.loads(value.pop("applied_controls_json") or "{}")
        return value

    def frozen_apps(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT * FROM frozen_apps ORDER BY updated_at DESC,bundle_id").fetchall()
        return [value for row in rows if (value := self._frozen_row(row)) is not None]

    def set_frozen_app(self, bundle_id: str, state: str, original_state: Any,
                       applied_controls: Any, expires_at: float | None = None,
                       profile_name: str | None = None,
                       last_error: str | None = None) -> None:
        if state not in {"Frozen", "Temporarily Active"}:
            raise ValueError("invalid frozen app state")
        now = time.time()
        with self._lock:
            self.connection.execute("""
              INSERT INTO frozen_apps(bundle_id,created_at,updated_at,state,
                original_state_json,expires_at,applied_controls_json,last_error,profile_name)
              VALUES(?,?,?,?,?,?,?,?,?)
              ON CONFLICT(bundle_id) DO UPDATE SET updated_at=excluded.updated_at,
                state=excluded.state,original_state_json=excluded.original_state_json,
                expires_at=excluded.expires_at,
                applied_controls_json=excluded.applied_controls_json,
                last_error=excluded.last_error,profile_name=excluded.profile_name
            """, (bundle_id, now, now, state, self._json(original_state), expires_at,
                  self._json(applied_controls),
                  None if last_error is None else str(last_error)[:2048], profile_name))

    def delete_frozen_app(self, bundle_id: str) -> None:
        with self._lock:
            self.connection.execute("DELETE FROM frozen_apps WHERE bundle_id=?", (bundle_id,))

    def record_notification_events(self, samples: Iterable[dict[str, Any]]) -> int:
        rows = []
        for sample in samples:
            rows.append((float(sample["timestamp"]), str(sample["bundle_id"])[:255],
                         None if sample.get("category_id") is None else
                         str(sample["category_id"])[:128], str(sample["source"])[:64],
                         str(sample["fingerprint"])[:64],
                         self._json(sample.get("metadata", {}))))
        if not rows:
            return 0
        with self._lock:
            before = self.connection.total_changes
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.executemany("""
                  INSERT OR IGNORE INTO notification_events(
                    timestamp,bundle_id,category_id,source,fingerprint,metadata_json)
                  VALUES(?,?,?,?,?,?)
                """, rows)
                self.connection.execute("COMMIT")
            except Exception:
                self.connection.execute("ROLLBACK")
                raise
            return self.connection.total_changes - before

    def notification_summary(self, since: float, limit: int = 100) -> list[dict[str, Any]]:
        count = min(500, max(1, int(limit)))
        with self._lock:
            rows = self.connection.execute("""
              SELECT bundle_id,COUNT(*) AS count,MAX(timestamp) AS latest,
                     COUNT(DISTINCT category_id) AS category_count
              FROM notification_events WHERE timestamp>=?
              GROUP BY bundle_id ORDER BY count DESC,bundle_id LIMIT ?
            """, (float(since), count)).fetchall()
        return [dict(row) for row in rows]

    def notification_events(self, limit: int = 200,
                            bundle_id: str | None = None) -> list[dict[str, Any]]:
        count = min(1000, max(1, int(limit)))
        query = "SELECT * FROM notification_events"
        parameters: tuple[Any, ...]
        if bundle_id is not None:
            query += " WHERE bundle_id=?"
            parameters = (bundle_id, count)
        else:
            parameters = (count,)
        query += " ORDER BY timestamp DESC,id DESC LIMIT ?"
        with self._lock:
            rows = self.connection.execute(query, parameters).fetchall()
        result = []
        for row in rows:
            value = dict(row)
            value["metadata"] = json.loads(value.pop("metadata_json") or "{}")
            result.append(value)
        return result

    def create_permission_timeout(self, *, bundle_id: str, resource: str,
                                  requested_policy: str, previous_policy: str,
                                  duration: str, expires_at: float | None,
                                  expiration_condition: str | None,
                                  provider: str) -> int:
        now = time.time()
        with self._lock:
            cursor = self.connection.execute("""
              INSERT INTO permission_timeouts(
                created_at,updated_at,bundle_id,resource,requested_policy,
                previous_policy,duration,expires_at,expiration_condition,state,provider)
              VALUES(?,?,?,?,?,?,?,?,?,'Active',?)
            """, (now, now, bundle_id, resource, requested_policy, previous_policy,
                  duration, expires_at, expiration_condition, provider))
            return int(cursor.lastrowid)

    def permission_timeouts(self, active_only: bool = False,
                            limit: int = 500) -> list[dict[str, Any]]:
        count = min(1000, max(1, int(limit)))
        query = "SELECT * FROM permission_timeouts"
        if active_only:
            query += " WHERE state='Active'"
        query += " ORDER BY updated_at DESC,id DESC LIMIT ?"
        with self._lock:
            rows = self.connection.execute(query, (count,)).fetchall()
        return [dict(row) for row in rows]

    def finish_permission_timeout(self, timeout_id: int, state: str,
                                  error: str | None = None) -> None:
        if state not in {"Expired", "Reverted", "Failed"}:
            raise ValueError("invalid permission timeout state")
        with self._lock:
            cursor = self.connection.execute("""
              UPDATE permission_timeouts SET state=?,updated_at=?,last_error=?
              WHERE id=? AND state='Active'
            """, (state, time.time(), None if error is None else str(error)[:2048],
                  int(timeout_id)))
            if cursor.rowcount != 1:
                raise ValueError("permission timeout is not active")

    def update_sensor_health(self, sensor: str, state: str, error: str | None = None,
                             success: bool = False, restart_increment: int = 0) -> None:
        now = time.time()
        with self._lock:
            self.connection.execute("""
              INSERT INTO sensor_health(sensor,state,last_success,last_failure,error,restart_count,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?)
              ON CONFLICT(sensor) DO UPDATE SET state=excluded.state,
                last_success=CASE WHEN ? THEN excluded.updated_at ELSE sensor_health.last_success END,
                last_failure=CASE WHEN ? THEN excluded.updated_at ELSE sensor_health.last_failure END,
                error=excluded.error,
                restart_count=sensor_health.restart_count + excluded.restart_count,
                updated_at=excluded.updated_at
            """, (sensor, state, now if success else None, None if success else now,
                  error, max(0, restart_increment), now, now, 1 if success else 0,
                  0 if success else 1))

    def sensor_health(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(row) for row in self.connection.execute(
                "SELECT * FROM sensor_health ORDER BY sensor").fetchall()]

    def apply_retention(self, table: str, older_than: float, batch_size: int = 1000) -> int:
        if table not in RETENTION_TABLES:
            raise ValueError("table is not retention-managed")
        batch_size = min(10000, max(1, int(batch_size)))
        column = RETENTION_TABLES[table]
        with self._lock:
            cursor = self.connection.execute(
                f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {column} < ? ORDER BY {column} LIMIT ?)",
                (float(older_than), batch_size))
            return max(0, cursor.rowcount)

    def integrity(self) -> str:
        with self._lock:
            return str(self.connection.execute("PRAGMA quick_check(1)").fetchone()[0])

    def tables(self) -> set[str]:
        with self._lock:
            return {str(row[0]) for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
