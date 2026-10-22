"""Business operations. Every state-changing operation runs inside a single
database transaction together with its audit record, and state moves only
through guarded transitions."""
from __future__ import annotations

import sqlite3
from typing import Any

from . import lifecycle as lc
from .clock import iso
from .context import Platform
from .security import DUMMY_HASH, verify_password
from .validation import ValidationContext, ValidationResult, parse_request, validate_request

PROVISION_SAFETY_MARGIN_SECONDS = 3600  # cap on how long a relative-lifetime env may sit un-Running before cleanup
MIN_EXTENSION_MINUTES = 15
MAX_EXTENSION_MINUTES = 7 * 24 * 60


class ServiceError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any = None):
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details


def _is_admin(user: dict[str, Any]) -> bool:
    return user["role"] == "admin"


class Service:
    def __init__(self, platform: Platform):
        self.p = platform
        self.s = platform.settings
        self.store = platform.store
        self.clock = platform.clock

    # ------------------------------------------------------------------- auth
    def authenticate(self, username: str, password: str) -> dict[str, Any] | None:
        with self.p.db.read() as c:
            user = self.store.get_user(c, username)
        ok = verify_password(password, user["pw_hash"] if user else DUMMY_HASH)  # constant-ish time
        if not user or not ok or user["disabled"]:
            with self.p.db.tx() as c:
                self.store.audit(c, username[:64], "auth.login_failed", None, {})
            return None
        with self.p.db.tx() as c:
            self.store.audit(c, username, "auth.login", None, {})
        return user

    def user_from_claims(self, claims: dict[str, Any]) -> dict[str, Any] | None:
        """Re-load the user on every request so role changes / disabling apply immediately."""
        with self.p.db.read() as c:
            user = self.store.get_user(c, claims["sub"])
        if not user or user["disabled"]:
            return None
        return user

    # ------------------------------------------------------------- validation
    def _validate(self, c, user: dict[str, Any], data: Any) -> tuple[Any, ValidationResult]:
        req, parse_errors = parse_request(data)
        if req is None:
            raise ServiceError(422, "validation_failed", "The request is invalid.", {"errors": parse_errors, "warnings": []})
        ctx = ValidationContext(
            settings=self.s, catalog=self.p.catalog(c), pricing=self.p.pricing, now=self.clock.now(), user=user,
            usage=self.store.usage(c, user["id"], req.project),
        )
        return req, validate_request(req, ctx)

    def preview(self, user: dict[str, Any], data: Any) -> dict[str, Any]:
        """Validate and estimate without creating anything."""
        with self.p.db.read() as c:
            req, res = self._validate(c, user, data)
        return {
            "valid": res.ok,
            "errors": res.errors,
            "warnings": res.warnings,
            "approvals_required": res.approvals,
            "estimate": res.estimate.as_dict() if res.estimate else None,
            "billable": req.provider != "demo",
        }

    # ------------------------------------------------------------ create/read
    def create_environment(self, user: dict[str, Any], data: Any, idempotency_key: str | None) -> tuple[dict[str, Any], bool]:
        """Returns (environment, created). A repeated Idempotency-Key returns the original
        environment (created=False) instead of provisioning a duplicate."""
        if idempotency_key is not None and not (8 <= len(idempotency_key) <= 100):
            raise ServiceError(400, "bad_idempotency_key", "Idempotency-Key must be 8-100 characters.")
        for attempt in range(2):
            try:
                with self.p.db.tx() as c:
                    if idempotency_key:
                        existing = self.store.find_by_idempotency(c, user["id"], idempotency_key)
                        if existing:
                            return self._view(c, existing, user), False
                    req, res = self._validate(c, user, data)
                    if not res.ok:
                        raise ServiceError(422, "validation_failed", "The request is invalid.", {"errors": res.errors, "warnings": res.warnings})
                    if req.provider != "demo" and not req.confirm:
                        raise ServiceError(422, "confirmation_required",
                                           "This creates billable infrastructure. Review the summary and confirm to launch.",
                                           {"errors": [{"field": "confirm", "message": "Explicit confirmation is required."}], "warnings": res.warnings})
                    plan, est, now = res.plan, res.estimate, self.clock.now()
                    assert plan is not None and est is not None
                    minutes = plan["lifetime_minutes"]
                    expires_at = now + minutes * 60 + (0 if plan["fixed_expiry"] else PROVISION_SAFETY_MARGIN_SECONDS)
                    needs_approval = bool(res.approvals)
                    env = self.store.insert_env(
                        c, id=self.store.new_env_id(), name=plan["name"], owner_id=user["id"], project=plan["project"],
                        purpose=plan["purpose"], provider=plan["provider"], region=plan["region"], template=plan["template"],
                        state=lc.PENDING, config=plan, est_hourly=est.hourly, est_total=est.total, est_complete=int(est.complete),
                        lifetime_minutes=minutes, fixed_expiry=int(plan["fixed_expiry"]), created_at=now, expires_at=expires_at,
                        auto_destroy=int(plan["auto_destroy"]),
                        retention_deadline=None if plan["auto_destroy"] else now + self.s.no_autodestroy_retention_minutes * 60,
                        notify_on_expiry=int(plan["notify"]), approval_required=int(needs_approval),
                        approval_reasons=res.approvals,
                        approved_by=None if needs_approval else (f"self:{user['username']}" if _is_admin(user) else "policy"),
                        idempotency_key=idempotency_key,
                    )
                    self.store.audit(c, user["username"], "environment.create", env["id"], {
                        "provider": env["provider"], "region": env["region"], "template": env["template"],
                        "vms": len(plan["vms"]), "lifetime_minutes": minutes, "auto_destroy": plan["auto_destroy"],
                        "est_total": round(est.total, 2), "approval_required": needs_approval,
                    })
                    self.store.add_log(c, env["id"], f"Environment requested by {user['username']}.")
                    if needs_approval:
                        self.store.add_log(c, env["id"], "Waiting for administrator approval: " + "; ".join(res.approvals), "warn")
                        self.store.add_alert(c, "info", "approval_needed", f"{user['username']} requested {env['name']} ({env['id']}): {'; '.join(res.approvals)}", env["id"])
                    else:
                        self.store.enqueue_job(c, env["id"], "provision", self.s.job_max_attempts, user["username"])
                    return self._view(c, self.store.get_env(c, env["id"]), user), True
            except sqlite3.IntegrityError:
                # Lost a race on (owner, idempotency_key): the other request created it; loop to return it.
                if attempt == 1 or not idempotency_key:
                    raise
        raise RuntimeError("unreachable")  # pragma: no cover

    def _owner_names(self, c) -> dict[int, str]:
        return {u["id"]: u["username"] for u in self.store.list_users(c)}

    def _view(self, c, env: dict[str, Any], viewer: dict[str, Any], owners: dict[int, str] | None = None) -> dict[str, Any]:
        owners = owners or self._owner_names(c)
        now = self.clock.now()
        cfg = env["config"]
        vms = cfg["vms"]
        state = env["state"]
        seconds_left = None if state in (lc.DESTROYED,) else int(env["expires_at"] - now)
        billable = lc.is_potentially_billable(state) and env["provider"] != "demo"
        notices = []
        if billable and seconds_left is not None and seconds_left < 0 and state != lc.DESTROYING:
            notices.append("Past its expiry and still exists; it may still be billing.")
        if state == lc.CLEANUP_FAILED:
            notices.append("Cleanup failed. Resources may still exist and be billing. An administrator can retry cleanup.")
        if state == lc.FAILED:
            notices.append("Provisioning failed. Partially created resources may exist; cleanup is scheduled automatically.")
        if not env["auto_destroy"] and state in (lc.RUNNING, lc.EXPIRING):
            notices.append(f"Automatic destruction is off; policy destroys it on {iso(env['retention_deadline'])}.")
        job = self.store.active_job(c, env["id"])
        return {
            "id": env["id"], "name": env["name"], "owner": owners.get(env["owner_id"], "unknown"), "project": env["project"],
            "purpose": env["purpose"], "provider": env["provider"], "region": env["region"], "template": env["template"],
            "state": state, "billable": billable, "simulated": env["provider"] == "demo", "notices": notices,
            "created_at": iso(env["created_at"]), "running_at": iso(env["running_at"]), "expires_at": iso(env["expires_at"]),
            "seconds_left": seconds_left, "lifetime_minutes": env["lifetime_minutes"], "auto_destroy": env["auto_destroy"],
            "retention_deadline": iso(env["retention_deadline"]), "extension_count": env["extension_count"],
            "approval": {"required": env["approval_required"], "approved_by": env["approved_by"], "reasons": env["approval_reasons"]},
            "estimate": {"hourly": round(env["est_hourly"] or 0, 4), "total": round(env["est_total"] or 0, 2), "complete": env["est_complete"]},
            "summary": {
                "vm_count": len(vms), "vcpu": None, "addons": cfg["addons"], "startup_scripts": cfg["startup_scripts"],
                "storage_gb": sum(v["boot_gb"] + sum(d["size_gb"] for d in v["data_disks"]) for v in vms),
                "access": cfg["network"]["access"], "ports": cfg["network"]["ports"], "allowed_cidrs": cfg["network"]["allowed_cidrs"],
                "vms": [{"name": v["name"], "size": v["size"], "image": v["image"]} for v in vms],
                "tags": cfg["tags"], "encryption": cfg["encryption"],
            },
            "cleanup": {"status": env["cleanup_status"], "error": env["cleanup_error"], "last_attempt": iso(env["last_cleanup_attempt"]),
                        "destroyed_at": iso(env["destroyed_at"])},
            "last_error": env["last_error"],
            "active_job": {"id": job["id"], "kind": job["kind"], "status": job["status"], "attempts": job["attempts"], "max_attempts": job["max_attempts"]} if job else None,
        }

    def _load(self, c, user: dict[str, Any], env_id: str, *, write: bool = False) -> dict[str, Any]:
        env = self.store.get_env(c, env_id)
        if env is None or (not _is_admin(user) and env["owner_id"] != user["id"]):
            raise ServiceError(404, "not_found", "Environment not found.")  # 404, not 403: don't reveal others' ids
        return env

    def list_environments(self, user: dict[str, Any], all_users: bool = False, include_destroyed: bool = True) -> list[dict[str, Any]]:
        with self.p.db.read() as c:
            owner = None if (all_users and _is_admin(user)) else user["id"]
            owners = self._owner_names(c)
            return [self._view(c, e, user, owners) for e in self.store.list_envs(c, owner, include_destroyed=include_destroyed)]

    def get_environment(self, user: dict[str, Any], env_id: str) -> dict[str, Any]:
        with self.p.db.read() as c:
            return self._view(c, self._load(c, user, env_id), user)

    def get_logs(self, user: dict[str, Any], env_id: str, after: int = 0) -> list[dict[str, Any]]:
        with self.p.db.read() as c:
            self._load(c, user, env_id)
            return [{"id": r["id"], "ts": iso(r["ts"]), "level": r["level"], "message": r["message"]} for r in self.store.get_logs(c, env_id, after)]

    def get_connection(self, user: dict[str, Any], env_id: str) -> dict[str, Any]:
        with self.p.db.read() as c:
            env = self._load(c, user, env_id)
        if env["state"] not in (lc.RUNNING, lc.EXPIRING):
            raise ServiceError(409, "not_running", f"Connection details are available while the environment is Running; it is {env['state']}.")
        return {"environment_id": env["id"], "connection": env["outputs"], "note": "Use the private key that matches the SSH public key you supplied. Private keys are never stored."}

    def get_jobs(self, user: dict[str, Any], env_id: str) -> list[dict[str, Any]]:
        with self.p.db.read() as c:
            self._load(c, user, env_id)
            return [self._job_view(j) for j in self.store.list_jobs(c, env_id=env_id)]

    @staticmethod
    def _job_view(j: dict[str, Any]) -> dict[str, Any]:
        return {"id": j["id"], "env_id": j["env_id"], "kind": j["kind"], "status": j["status"], "attempts": j["attempts"],
                "max_attempts": j["max_attempts"], "next_run_at": iso(j["next_run_at"]), "last_error": j["last_error"],
                "created_by": j["created_by"], "created_at": iso(j["created_at"]), "finished_at": iso(j["finished_at"])}

    # ---------------------------------------------------------------- destroy
    def begin_destroy(self, c, env: dict[str, Any], actor: str, reason: str) -> bool:
        """Move an environment to Destroying and enqueue the cleanup job in the caller's
        transaction. Returns False if it was not in a destroyable state or a job is already active."""
        if env["state"] == lc.PENDING:  # never provisioned: cancel without a job
            if not self.store.transition(c, env["id"], lc.DESTROYED, expect=[lc.PENDING], destroyed_at=self.clock.now(), cleanup_status="not_needed"):
                return False
            job = self.store.active_job(c, env["id"])
            if job and job["status"] == "queued":
                self.store.finish_job(c, job["id"], "dead", "Cancelled before provisioning.")
            self.store.add_log(c, env["id"], f"Cancelled before provisioning ({reason}).")
            self.store.audit(c, actor, "environment.cancel", env["id"], {"reason": reason})
            return True
        if self.store.active_job(c, env["id"]):
            return False
        if not self.store.transition(c, env["id"], lc.DESTROYING, expect=lc.DESTROYABLE, cleanup_status="queued", cleanup_error=None):
            return False
        self.store.enqueue_job(c, env["id"], "destroy", self.s.job_max_attempts, actor)
        self.store.add_log(c, env["id"], f"Destruction scheduled ({reason}).")
        self.store.audit(c, actor, "environment.destroy", env["id"], {"reason": reason})
        return True

    def destroy_environment(self, user: dict[str, Any], env_id: str) -> dict[str, Any]:
        with self.p.db.tx() as c:
            env = self._load(c, user, env_id)
            if env["state"] in (lc.DESTROYING, lc.DESTROYED):
                return self._view(c, env, user)  # idempotent
            if env["state"] == lc.PROVISIONING:
                raise ServiceError(409, "busy", "The environment is being provisioned. Destroy it once provisioning finishes or fails.")
            if not self.begin_destroy(c, env, user["username"], "requested by user" if env["owner_id"] == user["id"] else "requested by administrator"):
                raise ServiceError(409, "busy", "Another operation is already running for this environment.")
            return self._view(c, self.store.get_env(c, env_id), user)

    def retry_provision(self, user: dict[str, Any], env_id: str) -> dict[str, Any]:
        with self.p.db.tx() as c:
            env = self._load(c, user, env_id)
            if env["state"] != lc.FAILED:
                raise ServiceError(409, "not_failed", "Only environments in the Failed state can be retried.")
            if self.clock.now() >= env["expires_at"]:
                raise ServiceError(409, "expired", "This environment's lifetime has already passed; create a new one.")
            if self.store.enqueue_job(c, env_id, "provision", self.s.job_max_attempts, user["username"]) is None:
                raise ServiceError(409, "busy", "Another operation is already running for this environment.")
            self.store.audit(c, user["username"], "environment.retry_provision", env_id, {})
            self.store.add_log(c, env_id, f"Provisioning retry requested by {user['username']}.")
            return self._view(c, env, user)

    # ------------------------------------------------------------- approvals
    def approve_environment(self, admin: dict[str, Any], env_id: str, approve: bool) -> dict[str, Any]:
        with self.p.db.tx() as c:
            env = self.store.get_env(c, env_id)
            if env is None:
                raise ServiceError(404, "not_found", "Environment not found.")
            if env["state"] != lc.PENDING or not env["approval_required"] or env["approved_by"]:
                raise ServiceError(409, "not_pending_approval", "This environment is not waiting for approval.")
            if approve:
                self.store.update_env(c, env_id, approved_by=admin["username"])
                self.store.enqueue_job(c, env_id, "provision", self.s.job_max_attempts, admin["username"])
                self.store.add_log(c, env_id, f"Approved by {admin['username']}.")
                self.store.audit(c, admin["username"], "environment.approve", env_id, {})
            else:
                self.begin_destroy(c, env, admin["username"], "rejected by administrator")
                self.store.audit(c, admin["username"], "environment.reject", env_id, {})
            return self._view(c, self.store.get_env(c, env_id), admin)

    def retry_cleanup(self, admin: dict[str, Any], env_id: str) -> dict[str, Any]:
        with self.p.db.tx() as c:
            env = self.store.get_env(c, env_id)
            if env is None:
                raise ServiceError(404, "not_found", "Environment not found.")
            if env["state"] != lc.CLEANUP_FAILED:
                raise ServiceError(409, "not_cleanup_failed", "Only environments in the CleanupFailed state can be retried.")
            if not self.begin_destroy(c, env, admin["username"], "administrator retry"):
                raise ServiceError(409, "busy", "Another operation is already running for this environment.")
            self.store.audit(c, admin["username"], "environment.retry_cleanup", env_id, {})
            return self._view(c, self.store.get_env(c, env_id), admin)

    # ------------------------------------------------------------- extensions
    def request_extension(self, user: dict[str, Any], env_id: str, minutes: int, reason: str) -> dict[str, Any]:
        if not (MIN_EXTENSION_MINUTES <= minutes <= MAX_EXTENSION_MINUTES):
            raise ServiceError(422, "validation_failed", f"Extension must be {MIN_EXTENSION_MINUTES} minutes to 7 days.")
        reason = (reason or "").strip()[:200]
        with self.p.db.tx() as c:
            env = self._load(c, user, env_id)
            self._check_extendable(env, minutes)
            auto = minutes <= self.s.extension_auto_approve_minutes or _is_admin(user)
            ext_id = self.store.create_extension(c, env_id, user["username"], minutes, reason,
                                                 "approved" if auto else "pending", "policy" if auto else None)
            self.store.audit(c, user["username"], "extension.request", env_id, {"minutes": minutes, "auto_approved": auto, "reason": reason})
            if auto:
                self._apply_extension(c, env, minutes, "policy")
                status = "approved"
            else:
                self.store.add_alert(c, "info", "extension_requested", f"{user['username']} asks to extend {env['name']} ({env_id}) by {minutes} minutes: {reason or 'no reason given'}", env_id, dedupe=False)
                status = "pending"
            return {"id": ext_id, "status": status, "minutes": minutes, "environment": self._view(c, self.store.get_env(c, env_id), user)}

    def _check_extendable(self, env: dict[str, Any], minutes: int) -> None:
        if env["state"] not in (lc.RUNNING, lc.EXPIRING):
            raise ServiceError(409, "not_extendable", f"Only Running or Expiring environments can be extended; this one is {env['state']}.")
        if not env["auto_destroy"]:
            raise ServiceError(409, "not_extendable", "Automatic destruction is off for this environment, so there is no expiry to extend.")
        if env["extension_count"] >= self.s.max_extensions:
            raise ServiceError(409, "extension_limit", f"This environment has used all {self.s.max_extensions} allowed extensions.")
        from .catalog import TEMPLATES  # local import avoids a cycle at module load
        tpl = next(t for t in TEMPLATES if t["id"] == env["template"])
        new_total = env["expires_at"] + minutes * 60 - env["created_at"]
        if new_total > tpl["max_lifetime_minutes"] * 60:
            raise ServiceError(422, "exceeds_max_lifetime",
                               f"{tpl['name']} can live at most {tpl['max_lifetime_minutes'] // 60} hours in total; this extension would exceed that.")

    def _apply_extension(self, c, env: dict[str, Any], minutes: int, actor: str) -> None:
        """Update the authoritative expiry. The scheduler reads this column, so no other
        scheduled job needs to change."""
        new_expiry = env["expires_at"] + minutes * 60
        fields: dict[str, Any] = {"expires_at": new_expiry, "extension_count": env["extension_count"] + 1, "overdue_alerted": 0}
        warn_window = self.s.expiry_warn_minutes * 60
        if env["state"] == lc.EXPIRING and new_expiry - self.clock.now() > warn_window:
            self.store.transition(c, env["id"], lc.RUNNING, expect=[lc.EXPIRING], expiring_notified=0, **fields)
        else:
            self.store.update_env(c, env["id"], **fields)
        self.store.add_log(c, env["id"], f"Lifetime extended by {minutes} minutes (approved by {actor}); new expiry {iso(new_expiry)}.")
        self.store.audit(c, actor, "environment.extend", env["id"], {"minutes": minutes, "new_expires_at": iso(new_expiry)})

    def decide_extension(self, admin: dict[str, Any], ext_id: int, approve: bool) -> dict[str, Any]:
        with self.p.db.tx() as c:
            ext = self.store.get_extension(c, ext_id)
            if ext is None:
                raise ServiceError(404, "not_found", "Extension request not found.")
            if ext["status"] != "pending":
                raise ServiceError(409, "already_decided", "This request was already decided.")
            if approve:
                env = self.store.get_env(c, ext["env_id"])
                self._check_extendable(env, ext["minutes"])  # re-check: state may have changed since the request
                self.store.decide_extension(c, ext_id, "approved", admin["username"])
                self._apply_extension(c, env, ext["minutes"], admin["username"])
            else:
                self.store.decide_extension(c, ext_id, "rejected", admin["username"])
                self.store.audit(c, admin["username"], "extension.reject", ext["env_id"], {"extension_id": ext_id})
            return self.store.get_extension(c, ext_id)  # type: ignore[return-value]

    # -------------------------------------------------------------- dashboard
    def dashboard(self, user: dict[str, Any]) -> dict[str, Any]:
        now = self.clock.now()
        with self.p.db.read() as c:
            owner = None if _is_admin(user) else user["id"]
            envs = self.store.list_envs(c, owner)
            owners = self._owner_names(c)
            live = [e for e in envs if e["state"] != lc.DESTROYED]
            counts = {s: 0 for s in lc.ALL_STATES}
            for e in envs:
                counts[e["state"]] += 1
            upcoming = sorted((e for e in live if e["state"] in (lc.RUNNING, lc.EXPIRING) and e["auto_destroy"]), key=lambda e: e["expires_at"])
            running = [e for e in live if e["state"] in (lc.RUNNING, lc.EXPIRING)]
            ids = {e["id"] for e in envs}
            activity = [a for a in self.store.list_audit(c, 100) if a["target"] in ids][:12]
            pending_ext = len(self.store.list_extensions(c, status="pending")) if _is_admin(user) else None
            return {
                "scope": "all users" if owner is None else "your environments",
                "totals": {
                    "total": len(envs), "active": len(live), "running": counts[lc.RUNNING], "provisioning": counts[lc.PROVISIONING] + counts[lc.PENDING],
                    "failed": counts[lc.FAILED] + counts[lc.CLEANUP_FAILED], "expiring": counts[lc.EXPIRING],
                    "destroying": counts[lc.DESTROYING], "destroyed": counts[lc.DESTROYED], "by_state": counts,
                },
                "usage": {
                    "vms": sum(len(e["config"]["vms"]) for e in live),
                    "storage_gb": sum(v["boot_gb"] + sum(d["size_gb"] for d in v["data_disks"]) for e in live for v in e["config"]["vms"]),
                    "hourly_cost": round(sum((e["est_hourly"] or 0) for e in running), 4),
                    "cost_complete": all(e["est_complete"] for e in running),
                    "simulated_only": all(e["provider"] == "demo" for e in running) if running else False,
                    "note": "Estimated from list prices, not billing data.",
                },
                "upcoming_destruction": [
                    {"id": e["id"], "name": e["name"], "owner": owners.get(e["owner_id"], "unknown"), "state": e["state"],
                     "expires_at": iso(e["expires_at"]), "seconds_left": int(e["expires_at"] - now), "created_at": iso(e["created_at"]),
                     "running_at": iso(e["running_at"]), "lifetime_minutes": e["lifetime_minutes"]} for e in upcoming[:10]
                ],
                "recent_activity": [{"ts": iso(a["ts"]), "actor": a["actor"], "action": a["action"], "target": a["target"], "detail": a["detail"]} for a in activity],
                "pending_extension_requests": pending_ext,
            }

    # ----------------------------------------------------------------- admin
    def admin_overview(self) -> dict[str, Any]:
        with self.p.db.read() as c:
            return {
                "alerts": [{**a, "ts": iso(a["ts"])} for a in self.store.list_alerts(c)],
                "failed_jobs": [self._job_view(j) for j in self.store.list_jobs(c, statuses=["dead"], limit=50)],
                "queue": [self._job_view(j) for j in self.store.list_jobs(c, statuses=["queued", "running"], limit=50)],
                "pending_approvals": [
                    {"id": e["id"], "name": e["name"], "owner": self._owner_names(c).get(e["owner_id"]), "reasons": e["approval_reasons"],
                     "est_total": round(e["est_total"] or 0, 2), "created_at": iso(e["created_at"])}
                    for e in self.store.list_envs(c, states=[lc.PENDING]) if e["approval_required"] and not e["approved_by"]
                ],
                "pending_extensions": [
                    {**x, "created_at": iso(x["created_at"]), "decided_at": iso(x["decided_at"])} for x in self.store.list_extensions(c, status="pending")
                ],
            }

    def list_audit(self, limit: int = 200, target: str | None = None) -> list[dict[str, Any]]:
        with self.p.db.read() as c:
            return [{**a, "ts": iso(a["ts"])} for a in self.store.list_audit(c, min(limit, 500), target)]

    def acknowledge_alert(self, admin: dict[str, Any], alert_id: int) -> None:
        with self.p.db.tx() as c:
            if not self.store.ack_alert(c, alert_id):
                raise ServiceError(404, "not_found", "Alert not found.")
            self.store.audit(c, admin["username"], "alert.acknowledge", str(alert_id), {})

    def set_addon_enabled(self, admin: dict[str, Any], addon_id: str, enabled: bool) -> list[dict[str, Any]]:
        from .catalog import ADDONS
        if addon_id not in {a["id"] for a in ADDONS if a["available"]}:
            raise ServiceError(404, "not_found", "Unknown or unimplemented add-on.")
        with self.p.db.tx() as c:
            self.store.set_addon(c, addon_id, enabled)
            self.store.audit(c, admin["username"], "addon.enable" if enabled else "addon.disable", addon_id, {})
            return self.p.catalog(c).addons()

    def reconcile(self, admin: dict[str, Any]) -> dict[str, Any]:
        """Compare resources tagged in the cloud with the database. Orphans (resources of
        unknown or Destroyed environments) raise a critical alert."""
        report: dict[str, Any] = {"providers": {}, "orphans": [], "missing": []}
        with self.p.db.read() as c:
            envs = {e["id"]: e for e in self.store.list_envs(c)}
        for pid in self.p.providers.ids():
            try:
                resources = self.p.providers.get(pid).list_resources()
            except Exception as exc:  # noqa: BLE001 - report, don't crash
                report["providers"][pid] = {"ok": False, "error": str(exc)}
                continue
            report["providers"][pid] = {"ok": True, "resources": len(resources)}
            seen: set[str] = set()
            for r in resources:
                seen.add(r["env_id"])
                env = envs.get(r["env_id"])
                if env is None or env["state"] == lc.DESTROYED:
                    report["orphans"].append({"provider": pid, **r})
            for eid, env in envs.items():
                if env["provider"] == pid and env["state"] in (lc.RUNNING, lc.EXPIRING) and eid not in seen:
                    report["missing"].append({"provider": pid, "env_id": eid})
        with self.p.db.tx() as c:
            for o in report["orphans"]:
                self.store.add_alert(c, "critical", "orphan_resource", f"Resource {o['resource_id']} is tagged for {o['env_id']} but no active environment owns it.", o["env_id"])
            for m in report["missing"]:
                self.store.add_alert(c, "warning", "missing_resource", f"Environment {m['env_id']} is Running but the provider reports no resources.", m["env_id"])
            self.store.audit(c, admin["username"], "admin.reconcile", None, {"orphans": len(report["orphans"]), "missing": len(report["missing"])})
        return report
