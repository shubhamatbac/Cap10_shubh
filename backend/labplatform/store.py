"""All SQL lives here. Methods take an open connection ``c`` so callers can
compose several operations in one transaction (``with db.tx() as c``)."""
from __future__ import annotations

import json
import secrets
import sqlite3
from typing import Any, Iterable

from .clock import Clock
from .db import Database
from .lifecycle import ACTIVE_STATES, assert_transition, sources_for
from .security import redact

ENV_JSON_COLUMNS = {"config_json": "config", "outputs_json": "outputs", "resource_ids_json": "resource_ids", "approval_reasons": "approval_reasons"}
# Columns update_env may write (guards against column-name injection from callers).
ENV_WRITABLE = {
    "name", "state", "config_json", "est_hourly", "est_total", "est_complete", "lifetime_minutes", "running_at",
    "expires_at", "auto_destroy", "retention_deadline", "approval_required", "approval_reasons", "approved_by",
    "extension_count", "expiring_notified", "overdue_alerted", "outputs_json", "resource_ids_json", "last_error",
    "last_cleanup_attempt", "cleanup_status", "cleanup_error", "destroyed_at", "failed_at",
}


def _env(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)
    d["config"] = json.loads(d.pop("config_json"))
    d["outputs"] = json.loads(d.pop("outputs_json"))
    d["resource_ids"] = json.loads(d.pop("resource_ids_json"))
    d["approval_reasons"] = json.loads(d["approval_reasons"])
    for k in ("auto_destroy", "est_complete", "approval_required", "notify_on_expiry", "fixed_expiry", "expiring_notified", "overdue_alerted"):
        d[k] = bool(d[k])
    return d


def _rows(rows: Iterable[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(r) for r in rows]


class Store:
    def __init__(self, db: Database, clock: Clock):
        self.db = db
        self.clock = clock

    # ------------------------------------------------------------------ users
    def create_user(self, c, username: str, pw_hash: str, role: str, can_disable_autodestroy: bool = False) -> dict[str, Any]:
        c.execute(
            "INSERT INTO users(username, pw_hash, role, can_disable_autodestroy, created_at) VALUES (?,?,?,?,?)",
            (username, pw_hash, role, int(can_disable_autodestroy), self.clock.now()),
        )
        return self.get_user(c, username)  # type: ignore[return-value]

    def get_user(self, c, username: str) -> dict[str, Any] | None:
        row = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(row) if row else None

    def get_user_by_id(self, c, user_id: int) -> dict[str, Any] | None:
        row = c.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None

    def list_users(self, c) -> list[dict[str, Any]]:
        return _rows(c.execute("SELECT id, username, role, can_disable_autodestroy, disabled FROM users ORDER BY username"))

    def count_users(self, c) -> int:
        return c.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    # ----------------------------------------------------------- environments
    @staticmethod
    def new_env_id() -> str:
        return "env-" + secrets.token_hex(4)

    def insert_env(self, c, **f: Any) -> dict[str, Any]:
        f["config_json"] = json.dumps(f.pop("config"), sort_keys=True)
        if "approval_reasons" in f:
            f["approval_reasons"] = json.dumps(f["approval_reasons"])
        cols = ", ".join(f)
        marks = ", ".join("?" for _ in f)
        c.execute(f"INSERT INTO environments({cols}) VALUES ({marks})", tuple(f.values()))
        return self.get_env(c, f["id"])  # type: ignore[return-value]

    def get_env(self, c, env_id: str) -> dict[str, Any] | None:
        return _env(c.execute("SELECT * FROM environments WHERE id=?", (env_id,)).fetchone())

    def find_by_idempotency(self, c, owner_id: int, key: str) -> dict[str, Any] | None:
        return _env(c.execute("SELECT * FROM environments WHERE owner_id=? AND idempotency_key=?", (owner_id, key)).fetchone())

    def list_envs(self, c, owner_id: int | None = None, states: Iterable[str] | None = None, include_destroyed: bool = True) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM environments WHERE 1=1", []
        if owner_id is not None:
            sql += " AND owner_id=?"
            args.append(owner_id)
        if states is not None:
            states = list(states)
            sql += f" AND state IN ({','.join('?' for _ in states)})"
            args += states
        elif not include_destroyed:
            sql += " AND state != 'Destroyed'"
        sql += " ORDER BY created_at DESC"
        return [_env(r) for r in c.execute(sql, args)]  # type: ignore[misc]

    def update_env(self, c, env_id: str, **fields: Any) -> None:
        for k in list(fields):
            if k not in ENV_WRITABLE:
                raise ValueError(f"column {k!r} is not writable")
        for json_col in ("config_json", "outputs_json", "resource_ids_json", "approval_reasons"):
            if json_col in fields and not isinstance(fields[json_col], str):
                fields[json_col] = json.dumps(fields[json_col], sort_keys=True)
        sets = ", ".join(f"{k}=?" for k in fields)
        c.execute(f"UPDATE environments SET {sets} WHERE id=?", (*fields.values(), env_id))

    def transition(self, c, env_id: str, dst: str, expect: Iterable[str] | None = None, **fields: Any) -> bool:
        """Atomically move ``env_id`` to ``dst`` if it is currently in a legal source
        state (optionally narrowed by ``expect``). Returns False if the guard failed."""
        legal = set(sources_for(dst))
        if expect is not None:
            legal &= set(expect)
        if not legal:
            return False
        for k in fields:
            if k not in ENV_WRITABLE:
                raise ValueError(f"column {k!r} is not writable")
        for json_col in ("outputs_json", "resource_ids_json"):
            if json_col in fields and not isinstance(fields[json_col], str):
                fields[json_col] = json.dumps(fields[json_col], sort_keys=True)
        sets = ", ".join(["state=?"] + [f"{k}=?" for k in fields])
        marks = ",".join("?" for _ in legal)
        cur = c.execute(
            f"UPDATE environments SET {sets} WHERE id=? AND state IN ({marks})",
            (dst, *fields.values(), env_id, *sorted(legal)),
        )
        return cur.rowcount == 1

    def usage(self, c, owner_id: int, project: str) -> dict[str, int]:
        marks = ",".join("?" for _ in ACTIVE_STATES)
        envs = _rows(c.execute(f"SELECT owner_id, project, config_json FROM environments WHERE state IN ({marks})", ACTIVE_STATES))
        user_envs = [e for e in envs if e["owner_id"] == owner_id]
        return {
            "user_envs": len(user_envs),
            "user_vms": sum(len(json.loads(e["config_json"])["vms"]) for e in user_envs),
            "project_envs": sum(1 for e in envs if e["project"] == project),
        }

    # ------------------------------------------------------------------- jobs
    def enqueue_job(self, c, env_id: str, kind: str, max_attempts: int, created_by: str = "system", delay: float = 0.0) -> int | None:
        """Returns the job id, or None if an active job already exists for the env
        (enforced by a partial unique index, so concurrent callers cannot double-enqueue)."""
        now = self.clock.now()
        try:
            cur = c.execute(
                "INSERT INTO jobs(env_id, kind, status, max_attempts, next_run_at, created_by, created_at) VALUES (?,?,?,?,?,?,?)",
                (env_id, kind, "queued", max_attempts, now + delay, created_by, now),
            )
            return cur.lastrowid
        except sqlite3.IntegrityError:
            return None

    def active_job(self, c, env_id: str) -> dict[str, Any] | None:
        row = c.execute("SELECT * FROM jobs WHERE env_id=? AND status IN ('queued','running')", (env_id,)).fetchone()
        return dict(row) if row else None

    def claim_next_job(self, c, worker_id: str, lease_seconds: int) -> dict[str, Any] | None:
        """Atomically claim the oldest due job. Must run inside ``db.tx()``."""
        now = self.clock.now()
        row = c.execute(
            "SELECT * FROM jobs WHERE status='queued' AND next_run_at<=? ORDER BY next_run_at, id LIMIT 1", (now,)
        ).fetchone()
        if row is None:
            return None
        cur = c.execute(
            "UPDATE jobs SET status='running', claimed_by=?, lease_expires_at=?, started_at=?, attempts=attempts+1 "
            "WHERE id=? AND status='queued'",
            (worker_id, now + lease_seconds, now, row["id"]),
        )
        if cur.rowcount != 1:
            return None
        return dict(c.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone())

    def finish_job(self, c, job_id: int, status: str, error: str | None = None) -> None:
        c.execute(
            "UPDATE jobs SET status=?, last_error=?, finished_at=?, lease_expires_at=NULL WHERE id=?",
            (status, redact(error) if error else None, self.clock.now(), job_id),
        )

    def requeue_job(self, c, job_id: int, delay: float, error: str) -> None:
        c.execute(
            "UPDATE jobs SET status='queued', next_run_at=?, last_error=?, claimed_by=NULL, lease_expires_at=NULL WHERE id=?",
            (self.clock.now() + delay, redact(error), job_id),
        )

    def reap_expired_leases(self, c) -> list[dict[str, Any]]:
        """Jobs whose worker died mid-run (lease expired) go back to the queue so
        the work resumes. Terraform is idempotent, so a re-run is safe."""
        now = self.clock.now()
        rows = _rows(c.execute("SELECT * FROM jobs WHERE status='running' AND lease_expires_at IS NOT NULL AND lease_expires_at<?", (now,)))
        for r in rows:
            c.execute(
                "UPDATE jobs SET status='queued', next_run_at=?, claimed_by=NULL, lease_expires_at=NULL, last_error=? WHERE id=?",
                (now, "worker lease expired; job re-queued", r["id"]),
            )
        return rows

    def list_jobs(self, c, env_id: str | None = None, statuses: Iterable[str] | None = None, limit: int = 200) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM jobs WHERE 1=1", []
        if env_id:
            sql += " AND env_id=?"
            args.append(env_id)
        if statuses:
            statuses = list(statuses)
            sql += f" AND status IN ({','.join('?' for _ in statuses)})"
            args += statuses
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        return _rows(c.execute(sql, args))

    # ------------------------------------------------------------------- logs
    def add_log(self, c, env_id: str, message: str, level: str = "info") -> None:
        c.execute("INSERT INTO env_logs(env_id, ts, level, message) VALUES (?,?,?,?)",
                  (env_id, self.clock.now(), level, redact(message)[:4000]))

    def get_logs(self, c, env_id: str, after_id: int = 0, limit: int = 500) -> list[dict[str, Any]]:
        return _rows(c.execute("SELECT id, ts, level, message FROM env_logs WHERE env_id=? AND id>? ORDER BY id LIMIT ?", (env_id, after_id, limit)))

    # ------------------------------------------------------------------ audit
    def audit(self, c, actor: str, action: str, target: str | None = None, detail: dict[str, Any] | None = None) -> None:
        c.execute("INSERT INTO audit_log(ts, actor, action, target, detail_json) VALUES (?,?,?,?,?)",
                  (self.clock.now(), actor, action, target, redact(json.dumps(detail or {}, sort_keys=True))))

    def list_audit(self, c, limit: int = 200, target: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM audit_log", []
        if target:
            sql += " WHERE target=?"
            args.append(target)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        rows = _rows(c.execute(sql, args))
        for r in rows:
            r["detail"] = json.loads(r.pop("detail_json"))
        return rows

    # ----------------------------------------------------------------- alerts
    def add_alert(self, c, severity: str, kind: str, message: str, env_id: str | None = None, dedupe: bool = True) -> bool:
        if dedupe:
            exists = c.execute("SELECT 1 FROM alerts WHERE kind=? AND IFNULL(env_id,'')=? AND acknowledged=0", (kind, env_id or "")).fetchone()
            if exists:
                return False
        c.execute("INSERT INTO alerts(ts, severity, env_id, kind, message) VALUES (?,?,?,?,?)",
                  (self.clock.now(), severity, env_id, kind, redact(message)))
        return True

    def list_alerts(self, c, include_acknowledged: bool = False, limit: int = 200) -> list[dict[str, Any]]:
        sql = "SELECT * FROM alerts" + ("" if include_acknowledged else " WHERE acknowledged=0") + " ORDER BY id DESC LIMIT ?"
        return _rows(c.execute(sql, (limit,)))

    def ack_alert(self, c, alert_id: int) -> bool:
        return c.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,)).rowcount == 1

    # ------------------------------------------------------------- extensions
    def create_extension(self, c, env_id: str, requested_by: str, minutes: int, reason: str, status: str = "pending", decided_by: str | None = None) -> int:
        now = self.clock.now()
        cur = c.execute(
            "INSERT INTO extension_requests(env_id, requested_by, minutes, reason, status, decided_by, created_at, decided_at) VALUES (?,?,?,?,?,?,?,?)",
            (env_id, requested_by, minutes, reason, status, decided_by, now, now if status != "pending" else None),
        )
        return cur.lastrowid

    def get_extension(self, c, ext_id: int) -> dict[str, Any] | None:
        row = c.execute("SELECT * FROM extension_requests WHERE id=?", (ext_id,)).fetchone()
        return dict(row) if row else None

    def list_extensions(self, c, env_id: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
        sql, args = "SELECT * FROM extension_requests WHERE 1=1", []
        if env_id:
            sql += " AND env_id=?"
            args.append(env_id)
        if status:
            sql += " AND status=?"
            args.append(status)
        return _rows(c.execute(sql + " ORDER BY id DESC", args))

    def decide_extension(self, c, ext_id: int, status: str, decided_by: str) -> bool:
        return c.execute(
            "UPDATE extension_requests SET status=?, decided_by=?, decided_at=? WHERE id=? AND status='pending'",
            (status, decided_by, self.clock.now(), ext_id),
        ).rowcount == 1

    # ----------------------------------------------------------------- addons
    def addon_overrides(self, c) -> dict[str, bool]:
        return {r["addon_id"]: bool(r["enabled"]) for r in c.execute("SELECT * FROM addon_settings")}

    def set_addon(self, c, addon_id: str, enabled: bool) -> None:
        c.execute("INSERT INTO addon_settings(addon_id, enabled) VALUES (?,?) ON CONFLICT(addon_id) DO UPDATE SET enabled=excluded.enabled",
                  (addon_id, int(enabled)))
