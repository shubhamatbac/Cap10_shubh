"""SQLite persistence layer.

SQLite (WAL mode) is the MVP datastore: durable, zero-dependency and safe for
one API process plus a worker and scheduler. All SQL lives in ``store.py`` so a
PostgreSQL implementation can replace it later without touching business logic.
Timestamps are stored as epoch seconds (UTC).
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  pw_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('developer','admin')),
  can_disable_autodestroy INTEGER NOT NULL DEFAULT 0,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS environments (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  project TEXT NOT NULL,
  purpose TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL,
  region TEXT NOT NULL,
  template TEXT NOT NULL,
  state TEXT NOT NULL,
  config_json TEXT NOT NULL,
  est_hourly REAL,
  est_total REAL,
  est_complete INTEGER NOT NULL DEFAULT 1,
  lifetime_minutes INTEGER NOT NULL,
  fixed_expiry INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  running_at REAL,
  expires_at REAL NOT NULL,
  auto_destroy INTEGER NOT NULL DEFAULT 1,
  retention_deadline REAL,
  notify_on_expiry INTEGER NOT NULL DEFAULT 1,
  approval_required INTEGER NOT NULL DEFAULT 0,
  approval_reasons TEXT NOT NULL DEFAULT '[]',
  approved_by TEXT,
  extension_count INTEGER NOT NULL DEFAULT 0,
  expiring_notified INTEGER NOT NULL DEFAULT 0,
  overdue_alerted INTEGER NOT NULL DEFAULT 0,
  outputs_json TEXT NOT NULL DEFAULT '{}',
  resource_ids_json TEXT NOT NULL DEFAULT '[]',
  last_error TEXT,
  last_cleanup_attempt REAL,
  cleanup_status TEXT NOT NULL DEFAULT 'none',
  cleanup_error TEXT,
  destroyed_at REAL,
  failed_at REAL,
  idempotency_key TEXT,
  UNIQUE (owner_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idx_env_state ON environments(state);
CREATE INDEX IF NOT EXISTS idx_env_owner ON environments(owner_id);
CREATE INDEX IF NOT EXISTS idx_env_expires ON environments(expires_at);

CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  env_id TEXT NOT NULL REFERENCES environments(id),
  kind TEXT NOT NULL CHECK (kind IN ('provision','destroy')),
  status TEXT NOT NULL CHECK (status IN ('queued','running','succeeded','failed','dead')),
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL,
  next_run_at REAL NOT NULL,
  claimed_by TEXT,
  lease_expires_at REAL,
  last_error TEXT,
  created_by TEXT NOT NULL DEFAULT 'system',
  created_at REAL NOT NULL,
  started_at REAL,
  finished_at REAL
);
-- At most one active (queued or running) state-changing job per environment.
CREATE UNIQUE INDEX IF NOT EXISTS uq_job_active_per_env
  ON jobs(env_id) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS idx_jobs_due ON jobs(status, next_run_at);

CREATE TABLE IF NOT EXISTS env_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  env_id TEXT NOT NULL REFERENCES environments(id),
  ts REAL NOT NULL,
  level TEXT NOT NULL,
  message TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_logs_env ON env_logs(env_id, id);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT,
  detail_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  severity TEXT NOT NULL,
  env_id TEXT,
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  acknowledged INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS extension_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  env_id TEXT NOT NULL REFERENCES environments(id),
  requested_by TEXT NOT NULL,
  minutes INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
  decided_by TEXT,
  created_at REAL NOT NULL,
  decided_at REAL
);

CREATE TABLE IF NOT EXISTS addon_settings (
  addon_id TEXT PRIMARY KEY,
  enabled INTEGER NOT NULL
);

-- Resources created by the simulated "demo" provider, so that cleanup
-- verification in demo mode checks real persisted state rather than a flag.
CREATE TABLE IF NOT EXISTS demo_resources (
  resource_id TEXT PRIMARY KEY,
  env_id TEXT NOT NULL,
  kind TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def init(self) -> None:
        conn = self.connect()
        try:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        finally:
            conn.close()

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Write transaction. BEGIN IMMEDIATE takes the write lock up front, which
        makes read-then-write claim logic atomic across processes."""
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
        finally:
            conn.close()

    @contextmanager
    def read(self) -> Iterator[sqlite3.Connection]:
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()
