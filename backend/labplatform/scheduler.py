"""Server-side lifecycle controller.

The scheduler reads the authoritative ``expires_at`` from the database on every
sweep. It does not depend on any browser, session or UI process: closing the
UI, logging out or stopping the frontend cannot stop cleanup. Extending an
environment simply updates the same column, so there is no second schedule to
keep in sync.
"""
from __future__ import annotations

import logging
import threading
from typing import Any

from . import lifecycle as lc
from .context import Platform
from .service import Service

log = logging.getLogger("labplatform.scheduler")

OVERDUE_GRACE_SECONDS = 300


class Scheduler:
    def __init__(self, platform: Platform):
        self.p = platform
        self.s = platform.settings
        self.store = platform.store
        self.clock = platform.clock
        self.service = Service(platform)

    def run_forever(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                self.run_once()
            except Exception:  # noqa: BLE001
                log.exception("scheduler sweep failed")
            stop.wait(self.s.scheduler_interval_seconds)

    def run_once(self) -> dict[str, int]:
        """One sweep, in a single transaction so it is all-or-nothing and safe to run
        concurrently with API requests and workers."""
        stats = {"requeued": 0, "expiring": 0, "destroy_started": 0, "alerts": 0, "approvals_expired": 0}
        now = self.clock.now()
        warn = self.s.expiry_warn_minutes * 60
        grace = self.s.failed_cleanup_grace_minutes * 60
        with self.p.db.tx() as c:
            # 1. Jobs whose worker died mid-run go back to the queue.
            for job in self.store.reap_expired_leases(c):
                stats["requeued"] += 1
                self.store.add_log(c, job["env_id"], f"Worker lease expired during {job['kind']}; job re-queued.", "warn")
                self.store.add_alert(c, "warning", "lease_expired", f"A worker stopped responding during {job['kind']} of {job['env_id']}; it was re-queued.", job["env_id"], dedupe=False)

            envs = self.store.list_envs(c, include_destroyed=False)
            for env in envs:
                st, eid = env["state"], env["id"]
                expired = env["expires_at"] <= now

                # 2. Destroy anything past its expiry (or retention limit, or failed long enough).
                reason = None
                if st in (lc.RUNNING, lc.EXPIRING) and env["auto_destroy"] and expired:
                    reason = "lifetime expired"
                elif st in (lc.RUNNING, lc.EXPIRING) and not env["auto_destroy"] and env["retention_deadline"] and env["retention_deadline"] <= now:
                    reason = "retention limit reached (auto-destroy was disabled)"
                elif st == lc.FAILED and ((env["failed_at"] or env["created_at"]) + grace <= now or expired):
                    reason = "cleaning up after failed provisioning"
                if reason:
                    if self.service.begin_destroy(c, env, "scheduler", reason):
                        stats["destroy_started"] += 1
                    continue

                # 3. Warn, and mark Expiring, shortly before expiry.
                if st == lc.RUNNING and env["auto_destroy"] and 0 < env["expires_at"] - now <= warn:
                    if self.store.transition(c, eid, lc.EXPIRING, expect=[lc.RUNNING]):
                        stats["expiring"] += 1
                        self.store.add_log(c, eid, f"Expires in under {self.s.expiry_warn_minutes} minutes and will be destroyed automatically.", "warn")
                        if env["notify_on_expiry"] and not env["expiring_notified"]:
                            self.store.update_env(c, eid, expiring_notified=1)
                            self.store.add_alert(c, "info", "expiring", f"{env['name']} ({eid}) expires soon.", eid, dedupe=False)
                            stats["alerts"] += 1

                # 4. Alert when something still exists well past its planned end.
                if lc.is_potentially_billable(st) and expired and now - env["expires_at"] > OVERDUE_GRACE_SECONDS and not env["overdue_alerted"]:
                    self.store.update_env(c, eid, overdue_alerted=1)
                    why = "auto-destroy is disabled" if not env["auto_destroy"] else f"state is {st}"
                    self.store.add_alert(c, "error", "overdue", f"{env['name']} ({eid}) is past its expiry and still exists ({why}); it may still be billing.", eid)
                    stats["alerts"] += 1

                # 5. Self-heal: states that need a job but have none (e.g. crash between steps).
                if st == lc.DESTROYING and not self.store.active_job(c, eid):
                    self.store.enqueue_job(c, eid, "destroy", self.s.job_max_attempts, "scheduler")
                    self.store.add_log(c, eid, "Re-queued missing destroy job.", "warn")
                if st == lc.PENDING:
                    if env["approval_required"] and not env["approved_by"]:
                        if env["created_at"] + self.s.approval_ttl_minutes * 60 <= now:
                            if self.service.begin_destroy(c, env, "scheduler", "approval request expired"):
                                stats["approvals_expired"] += 1
                    elif not self.store.active_job(c, eid):
                        self.store.enqueue_job(c, eid, "provision", self.s.job_max_attempts, "scheduler")
                        self.store.add_log(c, eid, "Re-queued missing provision job.", "warn")
        return stats
