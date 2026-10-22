"""Simulated provider for demo mode and tests. It creates *no* cloud resources.

It persists fake resources in the database, so destroy verification checks real
state, and it can inject failures (``demo_failure``) so the failure/recovery
paths can be explored safely in the UI.
"""
from __future__ import annotations

import hashlib

from ..clock import Clock
from ..db import Database
from .base import Provider, ProviderContext, ProviderError, ProvisionResult, build_connection_info


class DemoProvider(Provider):
    id = "demo"

    def __init__(self, db: Database, clock: Clock, step_seconds: float = 2.0, max_attempts: int = 3):
        self.db, self.clock, self.step_seconds, self.max_attempts = db, clock, step_seconds, max_attempts

    # ---------------------------------------------------------- helpers
    def _step(self, ctx: ProviderContext, message: str) -> None:
        ctx.info(message)
        if self.step_seconds > 0:
            self.clock.sleep(self.step_seconds)

    def _put(self, env_id: str, resource_id: str, kind: str) -> None:
        with self.db.tx() as c:
            c.execute("INSERT OR IGNORE INTO demo_resources(resource_id, env_id, kind) VALUES (?,?,?)", (resource_id, env_id, kind))

    def _resources(self, env_id: str) -> list[str]:
        with self.db.read() as c:
            return [r["resource_id"] for r in c.execute(
                "SELECT resource_id FROM demo_resources WHERE env_id=? AND kind!='marker' ORDER BY resource_id", (env_id,))]

    @staticmethod
    def _n(env_id: str, name: str, mod: int = 200) -> int:
        return int(hashlib.sha256(f"{env_id}/{name}".encode()).hexdigest(), 16) % mod + 10

    # -------------------------------------------------------- lifecycle
    def provision(self, ctx: ProviderContext) -> ProvisionResult:
        plan, eid = ctx.plan, ctx.env_id
        ctx.info("[demo] Simulated provider: no real cloud resources are created.")
        self._step(ctx, "Creating network (simulated)")
        self._put(eid, f"demo-vpc-{eid}", "network")
        if plan.get("demo_failure") == "provision":
            ctx.warn("[demo] Injected failure: network created, VM creation will fail.")
            raise ProviderError("Simulated provisioning failure (demo_failure=provision). A partial network was left behind.", retryable=False)
        public = plan["network"]["access"] == "public"
        raw_vms = {}
        for vm in plan["vms"]:
            self._step(ctx, f"Creating VM {vm['name']} ({vm['size']}) (simulated)")
            self._put(eid, f"demo-vm-{eid}-{vm['name']}", "vm")
            for i, _ in enumerate(vm["data_disks"]):
                self._put(eid, f"demo-disk-{eid}-{vm['name']}-{i}", "disk")
            raw_vms[vm["name"]] = {
                "private_ip": f"10.20.0.{self._n(eid, vm['name'], 200)}",
                # 192.0.2.0/24 is TEST-NET-1: reserved for documentation, never routable.
                "public_ip": f"192.0.2.{self._n(eid, vm['name'], 200)}" if public else None,
            }
        raw: dict = {"vms": raw_vms}
        addons = plan.get("addons", [])
        if "bastion" in addons:
            self._step(ctx, "Creating bastion host (simulated)")
            self._put(eid, f"demo-bastion-{eid}", "vm")
            raw["bastion"] = {"public_ip": f"192.0.2.{self._n(eid, 'bastion', 200)}", "ssh_user": "ubuntu"}
        if "load_balancer" in addons:
            self._step(ctx, "Creating load balancer (simulated)")
            self._put(eid, f"demo-lb-{eid}", "lb")
            raw["load_balancer_dns"] = f"demo-lb-{eid}.example.invalid"
        if "object_storage" in addons:
            self._step(ctx, "Creating object storage bucket (simulated)")
            self._put(eid, f"demo-bucket-{eid}", "bucket")
            raw["bucket_name"] = f"demo-bucket-{eid}"
        ctx.info("[demo] Provisioning complete.")
        return ProvisionResult(
            connection=build_connection_info(plan, raw, demo=True),
            resource_ids=self._resources(eid),
            summary=f"{len(plan['vms'])} simulated VM(s)",
        )

    def destroy(self, ctx: ProviderContext) -> None:
        eid, mode = ctx.env_id, ctx.plan.get("demo_failure", "none")
        fail_budget = {"destroy_once": 1, "destroy_exhaust_retries": self.max_attempts}.get(mode, 0)
        if fail_budget:
            with self.db.tx() as c:
                used = c.execute("SELECT COUNT(*) FROM demo_resources WHERE env_id=? AND kind='marker'", (eid,)).fetchone()[0]
                if used < fail_budget:
                    c.execute("INSERT INTO demo_resources(resource_id, env_id, kind) VALUES (?,?,'marker')", (f"marker-{eid}-{used}", eid))
                    raise ProviderError(f"Simulated destroy failure {used + 1}/{fail_budget} (demo_failure={mode}).", retryable=True)
        self._step(ctx, "Deleting resources (simulated)")
        with self.db.tx() as c:
            c.execute("DELETE FROM demo_resources WHERE env_id=? AND kind!='marker'", (eid,))
        ctx.info("[demo] Resources deleted.")

    def verify_destroyed(self, ctx: ProviderContext) -> list[str]:
        return self._resources(ctx.env_id)

    def list_resources(self) -> list[dict[str, str]]:
        with self.db.read() as c:
            return [{"env_id": r["env_id"], "resource_id": r["resource_id"]}
                    for r in c.execute("SELECT env_id, resource_id FROM demo_resources WHERE kind!='marker'")]
