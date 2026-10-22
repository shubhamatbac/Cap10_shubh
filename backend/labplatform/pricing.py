"""Cost estimation.

Prices are a *reference snapshot* of public AWS on-demand list prices for
``us-east-1`` (Linux, shared tenancy). They are estimates only: they are never
presented as a bill, regions without a price table are reported as *unpriced*,
and usage-based charges (data transfer, S3 requests, LCUs) are not estimated.

Operators should verify the table against the AWS pricing page and can replace
or extend it with a JSON file (``LAB_PRICING_FILE``), format::

    {"aws": {"<region>": {"vm": {"t3.micro": 0.0104},
                          "ebs_gb_month": {"gp3": 0.08, "gp2": 0.10},
                          "public_ipv4_hour": 0.005, "alb_hour": 0.0225}}}
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HOURS_PER_MONTH = 730.0

REFERENCE_SOURCE = (
    "Reference snapshot of AWS public on-demand list prices (us-east-1, Linux). "
    "Verify before relying on it; override with LAB_PRICING_FILE."
)

_US_EAST_1 = {
    "vm": {"t3.micro": 0.0104, "t3.small": 0.0208, "t3.medium": 0.0416, "t3.large": 0.0832, "t3.xlarge": 0.1664},
    "ebs_gb_month": {"gp3": 0.08, "gp2": 0.10},
    "public_ipv4_hour": 0.005,
    "alb_hour": 0.0225,
}
DEFAULT_TABLE: dict[str, dict[str, Any]] = {"aws": {"us-east-1": _US_EAST_1}}


@dataclass
class LineItem:
    item: str
    hourly: float | None  # None = unpriced
    note: str = ""


@dataclass
class Estimate:
    hourly: float
    total: float
    lifetime_minutes: int
    items: list[LineItem] = field(default_factory=list)
    complete: bool = True
    notes: list[str] = field(default_factory=list)
    source: str = REFERENCE_SOURCE
    simulated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "hourly": round(self.hourly, 4),
            "total": round(self.total, 2),
            "lifetime_minutes": self.lifetime_minutes,
            "complete": self.complete,
            "simulated": self.simulated,
            "notes": self.notes,
            "source": self.source,
            "items": [{"item": i.item, "hourly": None if i.hourly is None else round(i.hourly, 4), "note": i.note} for i in self.items],
            "disclaimer": "Estimate only, not a bill. Actual cost is not tracked: no billing integration is configured.",
        }


class Pricing:
    def __init__(self, table: dict[str, dict[str, Any]] | None = None):
        self.table = table if table is not None else DEFAULT_TABLE

    @classmethod
    def load(cls, path: Path | None) -> "Pricing":
        if path is None:
            return cls()
        with open(path, encoding="utf-8") as fh:
            return cls(json.load(fh))

    def _region(self, provider: str, region: str) -> dict[str, Any] | None:
        # The demo provider is priced like AWS us-east-1 so the demo shows realistic numbers.
        key = "aws" if provider == "demo" else provider
        reg = "us-east-1" if provider == "demo" else region
        return self.table.get(key, {}).get(reg)

    def estimate(self, plan: dict[str, Any]) -> Estimate:
        provider, region = plan["provider"], plan["region"]
        lifetime = int(plan["lifetime_minutes"])
        prices = self._region(provider, region)
        est = Estimate(hourly=0.0, total=0.0, lifetime_minutes=lifetime, simulated=(provider == "demo"))
        if est.simulated:
            est.notes.append("Simulated provider: no real resources are created and nothing is billed. Figures show what the same lab would cost on AWS us-east-1.")
        if prices is None:
            est.complete = False
            est.items.append(LineItem("All resources", None, f"No price table for {provider}/{region}."))
            est.notes.append(f"Cost cannot be estimated for {provider} in {region}.")
            return est

        def add(label: str, hourly: float | None, note: str = "") -> None:
            est.items.append(LineItem(label, hourly, note))
            if hourly is None:
                est.complete = False
            else:
                est.hourly += hourly

        public = plan["network"]["access"] == "public"
        for vm in plan["vms"]:
            p = prices.get("vm", {}).get(vm["size"])
            add(f"VM {vm['name']} ({vm['size']})", p, "" if p is not None else "No price for this size.")
            gp = prices.get("ebs_gb_month", {})
            for label, gb, typ in [("boot disk", vm["boot_gb"], vm["boot_type"])] + [
                (f"data disk {i + 1}", d["size_gb"], d["type"]) for i, d in enumerate(vm["data_disks"])
            ]:
                rate = gp.get(typ)
                add(f"{vm['name']} {label} ({gb} GB {typ})", None if rate is None else gb * rate / HOURS_PER_MONTH,
                    "" if rate is not None else "No price for this disk type.")
            if public:
                ip = prices.get("public_ipv4_hour")
                add(f"{vm['name']} public IPv4", ip, "" if ip is not None else "No price for public IPv4.")

        addons = set(plan.get("addons", []))
        if "bastion" in addons:
            p = prices.get("vm", {}).get("t3.micro")
            add("Bastion host (t3.micro)", p)
            ip = prices.get("public_ipv4_hour")
            add("Bastion public IPv4", ip)
            gp = prices.get("ebs_gb_month", {}).get("gp3")
            add("Bastion boot disk (8 GB gp3)", None if gp is None else 8 * gp / HOURS_PER_MONTH)
        if "load_balancer" in addons:
            add("Application load balancer (hourly part)", prices.get("alb_hour"), "Usage-based LCU charges are not included.")
            est.notes.append("Load balancer usage charges (LCUs, data transfer) are not estimated.")
        if "object_storage" in addons:
            est.items.append(LineItem("Object storage bucket", 0.0, "Usage based; not estimated."))
            est.notes.append("Object storage and data transfer charges are usage based and not estimated.")
        if not est.complete:
            est.notes.append("Some resources have no price in the configured table, so this estimate is a lower bound.")
        est.total = est.hourly * lifetime / 60.0
        return est
