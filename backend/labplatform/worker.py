"""Durable job worker: claims provision/destroy jobs from the database, runs the
provider, verifies the outcome, and records the result.

Properties:
* Claiming is atomic (``BEGIN IMMEDIATE`` + guarded UPDATE), so two workers never run the same job.
* A partial unique index guarantees one active job per environment.
* Failed jobs retry with exponential backoff; a worker that dies leaves an expired
  lease which the scheduler re-queues.
* An environment is only marked Destroyed after the provider *independently verifies*
  that nothing is left, never merely because Terraform exited 0.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
import time
from typing import Any

from . import lifecycle as lc
from .context import Platform
from .providers.base import ProviderContext, ProviderError

log = logging.getLogger("labplatform.worker")


class Worker:
    def __init__(self, platform: Platform, worker_id: str | None = None):
        self.p = platform
        self.s = platform.settings
        self.store = platform.store
        self.clock = platform.clock
        self.id = worker_id or f"{socket.gethostname()}:{os.getpid()}:{threading.get_ident()}"

    # ------------------------------------------------------------ main loop
    def run_once(self) -> bool:
        """Process at most one job. Returns True if a job was processed."""
        with self.p.db.tx() as c:
            job = self.store.claim_next_job(c, self.id, self.s.lease_seconds)
        if job is None:
            return False
        try:
            if job["kind"] == "provision":
                self._provision(job)
            else:
                self._destroy(job)
        except Exception as exc:  # noqa: BLE001 - a bug must not wedge the job
            log.exception("unexpected error in job %s", job["id"])
            self._handle_failure(job, ProviderError(f"Internal error: {type(exc).__name__}: {exc}", retryable=True))
        return True

    def run_forever(self, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                if not self.run_once():
                    stop.wait(self.s.worker_poll_seconds)
            except Exception:  # noqa: BLE001
                log.exception("worker loop error")
                stop.wait(self.s.worker_poll_seconds)

    # -------------------------------------------------------------- helpers
    def _logger(self, env_id: str):
        def emit(message: str, level: str = "info") -> None:
            with self.p.db.tx() as c:
                self.store.add_log(c, env_id, message, level)
        return emit

    def _backoff(self, attempts: int) -> float:
        return float(min(self.s.backoff_max_seconds, self.s.backoff_base_seconds * (2 ** max(0, attempts - 1))))

    def _context(self, env: dict[str, Any]) -> ProviderContext:
        return ProviderContext(env_id=env["id"], plan=env["config"], expires_at=env["expires_at"], log=self._logger(env["id"]))

    # ------------------------------------------------------------ provision
    def _provision(self, job: dict[str, Any]) -> None:
        env_id = job["env_id"]
        with self.p.db.tx() as c:
            env = self.store.get_env(c, env_id)
            if env is None or env["state"] not in (lc.PENDING, lc.FAILED, lc.PROVISIONING):
                self.store.finish_job(c, job["id"], "dead", f"Environment is {env['state'] if env else 'missing'}; job is obsolete.")
                return
            if env["state"] in (lc.PENDING, lc.FAILED):
                self.store.transition(c, env_id, lc.PROVISIONING, expect=[lc.PENDING, lc.FAILED], last_error=None, failed_at=None)
                self.store.audit(c, job["created_by"], "environment.provision_start", env_id, {"attempt": job["attempts"]})
            self.store.add_log(c, env_id, f"Provisioning started (attempt {job['attempts']}/{job['max_attempts']}).")
        env = self._get(env_id)
        try:
            provider = self.p.providers.get(env["provider"])
            result = provider.provision(self._context(env))
        except ProviderError as exc:
            self._handle_failure(job, exc)
            return
        now = self.clock.now()
        with self.p.db.tx() as c:
            fields: dict[str, Any] = {"running_at": now, "outputs_json": result.connection, "resource_ids_json": result.resource_ids, "last_error": None}
            if not env["fixed_expiry"]:
                fields["expires_at"] = now + env["lifetime_minutes"] * 60  # lifetime starts when the lab is usable
            ok = self.store.transition(c, env_id, lc.RUNNING, expect=[lc.PROVISIONING], **fields)
            self.store.finish_job(c, job["id"], "succeeded")
            if ok:
                self.store.add_log(c, env_id, f"Environment is running ({result.summary}).")
                self.store.audit(c, "worker", "environment.running", env_id, {"resources": len(result.resource_ids)})
            else:
                self.store.add_log(c, env_id, "Provisioning finished but the environment was no longer in Provisioning state.", "warn")

    def _get(self, env_id: str) -> dict[str, Any]:
        with self.p.db.read() as c:
            return self.store.get_env(c, env_id)  # type: ignore[return-value]

    # -------------------------------------------------------------- destroy
    def _destroy(self, job: dict[str, Any]) -> None:
        env_id = job["env_id"]
        with self.p.db.tx() as c:
            env = self.store.get_env(c, env_id)
            if env is None or env["state"] != lc.DESTROYING:
                self.store.finish_job(c, job["id"], "dead", f"Environment is {env['state'] if env else 'missing'}; job is obsolete.")
                return
            self.store.update_env(c, env_id, last_cleanup_attempt=self.clock.now(), cleanup_status="running")
            self.store.add_log(c, env_id, f"Cleanup started (attempt {job['attempts']}/{job['max_attempts']}).")
        ctx = self._context(env)
        try:
            provider = self.p.providers.get(env["provider"])
            provider.destroy(ctx)
            leftovers = provider.verify_destroyed(ctx)
            if leftovers:
                preview = "; ".join(leftovers[:5]) + (f" (+{len(leftovers) - 5} more)" if len(leftovers) > 5 else "")
                raise ProviderError(f"Cleanup verification failed: {len(leftovers)} resource(s) still exist: {preview}", retryable=True)
        except ProviderError as exc:
            self._handle_failure(job, exc)
            return
        with self.p.db.tx() as c:
            ok = self.store.transition(c, env_id, lc.DESTROYED, expect=[lc.DESTROYING], destroyed_at=self.clock.now(),
                                       cleanup_status="verified", cleanup_error=None)
            self.store.finish_job(c, job["id"], "succeeded")
            if ok:
                self.store.add_log(c, env_id, "Cleanup verified: no resources remain. Environment destroyed.")
                self.store.audit(c, "worker", "environment.destroyed", env_id, {"verified": True})

    # -------------------------------------------------------------- failure
    def _handle_failure(self, job: dict[str, Any], exc: ProviderError) -> None:
        env_id, kind, msg = job["env_id"], job["kind"], str(exc)
        retry = exc.retryable and job["attempts"] < job["max_attempts"]
        with self.p.db.tx() as c:
            if retry:
                delay = self._backoff(job["attempts"])
                self.store.requeue_job(c, job["id"], delay, msg)
                self.store.add_log(c, env_id, f"{kind} attempt {job['attempts']}/{job['max_attempts']} failed: {msg}. Retrying in {int(delay)}s.", "warn")
                if kind == "destroy":
                    self.store.update_env(c, env_id, cleanup_status="retrying", cleanup_error=msg[:500])
                return
            self.store.finish_job(c, job["id"], "dead", msg)
            self.store.add_log(c, env_id, f"{kind} failed permanently: {msg}", "error")
            if kind == "provision":
                self.store.transition(c, env_id, lc.FAILED, expect=[lc.PROVISIONING], failed_at=self.clock.now(), last_error=msg[:500])
                self.store.audit(c, "worker", "environment.provision_failed", env_id, {"error": msg[:300]})
                self.store.add_alert(c, "error", "provision_failed", f"Provisioning of {env_id} failed: {msg[:300]}. Partial resources are cleaned up automatically.", env_id)
            else:
                self.store.transition(c, env_id, lc.CLEANUP_FAILED, expect=[lc.DESTROYING], cleanup_status="failed", cleanup_error=msg[:500])
                self.store.audit(c, "worker", "environment.cleanup_failed", env_id, {"error": msg[:300]})
                self.store.add_alert(
                    c, "critical", "cleanup_failed",
                    f"Cleanup of {env_id} failed after {job['attempts']} attempt(s) and it may still be billing: {msg[:300]}. Inspect it under Admin and retry cleanup.", env_id)
