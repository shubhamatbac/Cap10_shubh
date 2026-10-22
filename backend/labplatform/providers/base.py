"""Provider adapter interface.

A provider turns a *normalized plan* into infrastructure and back. Adding a
cloud means adding one adapter module and registering it in ``registry.py``;
nothing else in the platform is provider specific.
"""
from __future__ import annotations

import abc
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from ..catalog import IMAGES


class ProviderError(Exception):
    """Raised by adapters. ``retryable`` failures are retried with backoff."""

    def __init__(self, message: str, retryable: bool = True):
        super().__init__(message)
        self.retryable = retryable


@dataclass
class ProvisionResult:
    connection: dict[str, Any]  # approved, non-secret connection details only
    resource_ids: list[str] = field(default_factory=list)
    summary: str = ""


@dataclass
class ProviderContext:
    env_id: str
    plan: dict[str, Any]
    expires_at: float
    log: Callable[[str, str], None]  # log(message, level="info")

    def info(self, message: str) -> None:
        self.log(message, "info")

    def warn(self, message: str) -> None:
        self.log(message, "warn")


class Provider(abc.ABC):
    id: str

    @abc.abstractmethod
    def provision(self, ctx: ProviderContext) -> ProvisionResult: ...

    @abc.abstractmethod
    def destroy(self, ctx: ProviderContext) -> None:
        """Delete everything belonging to ``ctx.env_id``. Must be idempotent."""

    @abc.abstractmethod
    def verify_destroyed(self, ctx: ProviderContext) -> list[str]:
        """Independently check the cloud. Returns descriptions of anything still
        present; an empty list means the environment is verifiably gone. Raise
        ProviderError if the check itself could not be completed."""

    def list_resources(self) -> list[dict[str, str]]:
        """All platform-tagged resources: [{'env_id':..., 'resource_id':...}]. Used for reconciliation."""
        raise ProviderError("This provider does not support reconciliation.", retryable=False)


_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DNS = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
_BUCKET = re.compile(r"^[a-z0-9.-]{3,63}$")
_ID = re.compile(r"^[A-Za-z0-9:/._-]{1,200}$")


def _ip(value: Any) -> str | None:
    if not isinstance(value, str) or not _IPV4.match(value):
        return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return None
    return value


def build_connection_info(plan: dict[str, Any], raw: dict[str, Any], *, demo: bool = False) -> dict[str, Any]:
    """Whitelist what Terraform (or a demo) returned into the connection details the
    UI may show. Unknown keys, sensitive outputs and malformed values are dropped."""
    vms_out = []
    raw_vms = raw.get("vms") if isinstance(raw.get("vms"), dict) else {}
    for vm in plan["vms"]:
        r = raw_vms.get(vm["name"], {}) if isinstance(raw_vms, dict) else {}
        user = IMAGES[vm["image"]]["ssh_user"]
        public_ip, private_ip = _ip(r.get("public_ip")), _ip(r.get("private_ip"))
        host = public_ip or private_ip
        vms_out.append({
            "name": vm["name"], "size": vm["size"], "image": vm["image"], "ssh_user": user,
            "public_ip": public_ip, "private_ip": private_ip,
            "ssh_command": f"ssh {user}@{host}" if host else None,
        })
    info: dict[str, Any] = {"vms": vms_out, "demo": demo}
    bastion = raw.get("bastion")
    if isinstance(bastion, dict) and _ip(bastion.get("public_ip")):
        info["bastion"] = {"public_ip": bastion["public_ip"], "ssh_user": bastion.get("ssh_user", "ubuntu") if isinstance(bastion.get("ssh_user"), str) else "ubuntu"}
    lb = raw.get("load_balancer_dns")
    if isinstance(lb, str) and _DNS.match(lb):
        info["load_balancer_dns"] = lb
    bucket = raw.get("bucket_name")
    if isinstance(bucket, str) and _BUCKET.match(bucket):
        info["bucket_name"] = bucket
    return info


def clean_resource_ids(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [v for v in values if isinstance(v, str) and _ID.match(v)][:500]
