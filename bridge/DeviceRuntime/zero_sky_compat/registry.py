"""Exact-artifact, exact-environment evidence registry with append-only history."""
from contextlib import contextmanager
import json
from pathlib import Path
import sqlite3
import time
from .failures import fingerprint


class Registry:
    def __init__(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS environments (key TEXT PRIMARY KEY, model TEXT);
                CREATE TABLE IF NOT EXISTS reports (
                    key TEXT PRIMARY KEY, component TEXT, source_hash TEXT,
                    environment_hash TEXT, status TEXT, updated REAL, report TEXT);
                CREATE TABLE IF NOT EXISTS history (
                    id INTEGER PRIMARY KEY, key TEXT, updated REAL, report TEXT);
                CREATE TABLE IF NOT EXISTS failures (
                    fingerprint TEXT PRIMARY KEY, codes TEXT, phase TEXT,
                    count INTEGER, last_seen REAL);
                CREATE TABLE IF NOT EXISTS component_failures (
                    report_key TEXT, fingerprint TEXT, phase TEXT,
                    count INTEGER, last_seen REAL,
                    PRIMARY KEY(report_key, fingerprint, phase));
            ''')

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(str(self.path), timeout=30)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def save_environment(self, environment):
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO environments VALUES (?, ?)',
                       (environment.fingerprint, json.dumps(environment.canonical(), sort_keys=True)))

    def save(self, report):
        value = report.to_dict() if hasattr(report, 'to_dict') else report
        key = report.key
        serialized = json.dumps(value, sort_keys=True)
        now = time.time()
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?, ?, ?, ?)',
                       (key, value['component'], value['source_hash'], value['environment_hash'], value['status'], now, serialized))
            db.execute('INSERT INTO history(key, updated, report) VALUES (?, ?, ?)', (key, now, serialized))

    def get(self, key):
        with self.connect() as db:
            row = db.execute('SELECT report FROM reports WHERE key=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self, limit=500):
        with self.connect() as db:
            rows = db.execute('SELECT key, report FROM reports ORDER BY updated DESC LIMIT ?', (min(limit, 1000),)).fetchall()
        return [dict(json.loads(row[1]), registry_key=row[0]) for row in rows]

    def known_failure(self, key, staged_hash, backend):
        permanent = {'LAUNCHCTL_ABI_INCOMPATIBLE', 'XPC_REGISTRATION_FAILED',
                     'DYLD_FAILURE', 'SIGNATURE_INVALID', 'SANDBOX_DENIED',
                     'MISSING_ENTITLEMENT', 'UNSUPPORTED_API', 'ARCHITECTURE_MISMATCH'}
        with self.connect() as db:
            rows = db.execute('SELECT report FROM history WHERE key=? ORDER BY id DESC', (key,)).fetchall()
        for row in rows:
            value = json.loads(row[0])
            if value.get('status') in ('PASS', 'ADAPTED', 'DEGRADED'):
                return None
            if value.get('status') == 'BLOCKED' and value.get('staged_hash') == staged_hash and value.get('transaction', {}).get('backend') == backend:
                if permanent & {i['code'] for i in value.get('issues', [])}:
                    return value
        return None

    def learn(self, text, phase='runtime'):
        value = fingerprint(text, phase)
        with self.connect() as db:
            db.execute('''INSERT INTO failures VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(fingerprint) DO UPDATE SET count=count+1, last_seen=excluded.last_seen''',
                (value['fingerprint'], json.dumps(value['codes']), phase, time.time()))
        return value

    def record_component_failure(self, report_key, text, phase='runtime'):
        value = self.learn(text, phase)
        with self.connect() as db:
            db.execute('''INSERT INTO component_failures VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(report_key, fingerprint, phase) DO UPDATE
                SET count=count+1, last_seen=excluded.last_seen''',
                (report_key, value['fingerprint'], phase, time.time()))
            count = db.execute('''SELECT count FROM component_failures
                WHERE report_key=? AND fingerprint=? AND phase=?''',
                (report_key, value['fingerprint'], phase)).fetchone()[0]
        return {**value, 'count': count, 'quarantined': count >= 3}

    def quarantined(self, report_key):
        with self.connect() as db:
            row = db.execute('''SELECT MAX(count) FROM component_failures
                WHERE report_key=?''', (report_key,)).fetchone()
        return bool(row and row[0] is not None and row[0] >= 3)
