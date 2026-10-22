"""Server-side validation of environment requests.

``validate_request`` is a pure function: it takes the parsed request, the
requesting user, current usage counts and settings, and returns either errors or
a *normalized plan*. Only the normalized plan is ever handed to a provider, and
it contains nothing but catalog identifiers, bounded numbers and validated
strings.
"""
from __future__ import annotations

import base64
import ipaddress
import math
import re
import struct
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import catalog as cat
from .catalog import Catalog
from .clock import parse_iso
from .config import Settings
from .pricing import Estimate, Pricing

NAME_RE = re.compile(r"^[a-z]([a-z0-9-]{0,28}[a-z0-9])?$")
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}$")
TAG_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:/-]{0,62}$")
TAG_VALUE_RE = re.compile(r"^[A-Za-z0-9_ .:/@=+-]{0,128}$")
PURPOSE_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,140}$")
RESERVED_TAG_PREFIXES = ("aws:", "lab:")
MAX_CUSTOM_TAGS = 5
MAX_CIDRS = 5

SSH_KEY_TYPES = {"ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"}


# ---------------------------------------------------------------- request models
class DataDisk(BaseModel):
    model_config = ConfigDict(extra="forbid")
    size_gb: int
    type: str = "gp3"


class VMSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    size: str
    image: str
    boot_gb: int = 20
    boot_type: str = "gp3"
    data_disks: list[DataDisk] = Field(default_factory=list)


class NetworkSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    access: Literal["public", "private"] = "public"
    allowed_cidrs: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=lambda: [22])


class LifetimeSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    minutes: int | None = None
    expires_at: str | None = None
    auto_destroy: bool = True
    notify: bool = True


class EnvRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    provider: str
    region: str
    template: str
    project: str
    purpose: str
    ssh_public_key: str
    vms: list[VMSpec]
    lifetime: LifetimeSpec
    network: NetworkSpec = Field(default_factory=NetworkSpec)
    tags: dict[str, str] = Field(default_factory=dict)
    encryption: bool = True
    addons: list[str] = Field(default_factory=list)
    startup_scripts: list[str] = Field(default_factory=list)
    demo_failure: Literal["none", "provision", "destroy_once", "destroy_exhaust_retries"] = "none"
    confirm: bool = False


def parse_request(data: Any) -> tuple[EnvRequest | None, list[dict[str, str]]]:
    try:
        return EnvRequest.model_validate(data), []
    except ValidationError as exc:
        errors = []
        for e in exc.errors():
            loc = ".".join(str(p) for p in e["loc"]) or "body"
            errors.append({"field": loc, "message": e["msg"]})
        return None, errors


# ------------------------------------------------------------------ SSH key check
def check_ssh_public_key(raw: str) -> tuple[str | None, str | None]:
    """Returns (normalized_key, error)."""
    if any(c in raw for c in "\r\n\x00"):
        return None, "SSH public key must be a single line."
    parts = raw.strip().split()
    if len(parts) < 2:
        return None, "SSH public key must look like 'ssh-ed25519 AAAA… comment'."
    key_type, b64 = parts[0], parts[1]
    if key_type not in SSH_KEY_TYPES:
        return None, f"Unsupported SSH key type {key_type!r}. Use ed25519, ECDSA or RSA."
    try:
        blob = base64.b64decode(b64, validate=True)
        (tlen,) = struct.unpack(">I", blob[:4])
        embedded = blob[4:4 + tlen].decode("ascii")
    except Exception:
        return None, "SSH public key is not valid base64 key data."
    if embedded != key_type:
        return None, "SSH public key type does not match its key data."
    if key_type == "ssh-rsa":
        try:
            off = 4 + tlen
            (elen,) = struct.unpack(">I", blob[off:off + 4])
            off += 4 + elen
            (nlen,) = struct.unpack(">I", blob[off:off + 4])
            modulus = blob[off + 4: off + 4 + nlen]
            bits = int.from_bytes(modulus, "big").bit_length()
        except Exception:
            return None, "SSH RSA key data is malformed."
        if bits < 2048:
            return None, "RSA keys must be at least 2048 bits."
    return f"{key_type} {b64}", None


# --------------------------------------------------------------------- result type
@dataclass
class ValidationContext:
    settings: Settings
    catalog: Catalog
    pricing: Pricing
    now: float
    user: dict[str, Any]  # username, role, can_disable_autodestroy
    usage: dict[str, int] = field(default_factory=dict)  # user_envs, user_vms, project_envs


@dataclass
class ValidationResult:
    errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    approvals: list[str] = field(default_factory=list)  # reasons an admin must approve
    plan: dict[str, Any] | None = None
    estimate: Estimate | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def err(self, field_name: str, message: str) -> None:
        self.errors.append({"field": field_name, "message": message})


def _is_admin(user: dict[str, Any]) -> bool:
    return user.get("role") == "admin"


def _check_cidr(raw: str, user: dict[str, Any], res: ValidationResult, wide: list[str]) -> str | None:
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        res.err("network.allowed_cidrs", f"{raw!r} is not a valid CIDR block, e.g. 203.0.113.7/32.")
        return None
    if net.prefixlen == 0:
        if not _is_admin(user):
            res.err("network.allowed_cidrs", "Opening access to the whole internet (0.0.0.0/0 or ::/0) needs an administrator. Use your own IP as a /32.")
            return None
        wide.append(str(net))
        return str(net)
    limit = 24 if net.version == 4 else 64
    if net.prefixlen < limit:
        wide.append(str(net))
    return str(net)


def validate_request(req: EnvRequest, ctx: ValidationContext) -> ValidationResult:
    res = ValidationResult()
    s, catalog, user = ctx.settings, ctx.catalog, ctx.user

    # ---- identity fields
    if not NAME_RE.match(req.name):
        res.err("name", "Use 1-30 lowercase letters, digits or hyphens, starting with a letter.")
    if not PROJECT_RE.match(req.project):
        res.err("project", "Project must be 2-31 lowercase letters, digits or hyphens.")
    if not PURPOSE_RE.match(req.purpose.strip() or "\x00"):
        res.err("purpose", "Describe the purpose in 1-140 characters.")

    # ---- provider / region / template
    provider = catalog.provider(req.provider)
    if provider is None:
        res.err("provider", f"Unknown provider {req.provider!r}.")
    elif not provider["available"]:
        res.err("provider", f"{provider['name']} is not available: {provider.get('reason', 'not implemented')}")
    if req.region not in s.allowed_regions:
        res.err("region", f"Region {req.region!r} is not allowed. Choose one of: {', '.join(s.allowed_regions)}.")
    tpl = catalog.template(req.template)
    if tpl is None:
        res.err("template", f"Unknown template {req.template!r}.")
        return res
    if not tpl["available"]:
        res.err("template", f"{tpl['name']} is not available: {tpl.get('reason', 'not implemented')}")
        return res

    # ---- compute
    vms = req.vms
    max_vms = min(tpl["max_vms"], s.max_vms_per_env)
    if not (tpl["min_vms"] <= len(vms) <= max_vms):
        res.err("vms", f"{tpl['name']} needs between {tpl['min_vms']} and {max_vms} VMs; you requested {len(vms)}.")
    seen: set[str] = set()
    norm_vms: list[dict[str, Any]] = []
    for i, vm in enumerate(vms):
        f = f"vms.{i}"
        if not NAME_RE.match(vm.name):
            res.err(f"{f}.name", "VM names use 1-30 lowercase letters, digits or hyphens, starting with a letter.")
        if vm.name in seen:
            res.err(f"{f}.name", f"Duplicate VM name {vm.name!r}.")
        seen.add(vm.name)
        if vm.size not in cat.SIZES:
            res.err(f"{f}.size", f"Unknown size {vm.size!r}.")
        elif vm.size not in tpl["allowed_sizes"]:
            res.err(f"{f}.size", f"{vm.size} is not offered for {tpl['name']}. Choose one of: {', '.join(tpl['allowed_sizes'])}.")
        if vm.image not in cat.IMAGES:
            res.err(f"{f}.image", f"{vm.image!r} is not an approved image.")
        if not (cat.BOOT_GB_RANGE[0] <= vm.boot_gb <= cat.BOOT_GB_RANGE[1]):
            res.err(f"{f}.boot_gb", f"Boot disk must be {cat.BOOT_GB_RANGE[0]}-{cat.BOOT_GB_RANGE[1]} GB.")
        if vm.boot_type not in cat.DISK_TYPES:
            res.err(f"{f}.boot_type", f"Disk type must be one of {', '.join(cat.DISK_TYPES)}.")
        if len(vm.data_disks) > cat.MAX_DATA_DISKS_PER_VM:
            res.err(f"{f}.data_disks", f"At most {cat.MAX_DATA_DISKS_PER_VM} data disks per VM.")
        for j, d in enumerate(vm.data_disks):
            if not (cat.DATA_GB_RANGE[0] <= d.size_gb <= cat.DATA_GB_RANGE[1]):
                res.err(f"{f}.data_disks.{j}.size_gb", f"Data disk must be {cat.DATA_GB_RANGE[0]}-{cat.DATA_GB_RANGE[1]} GB.")
            if d.type not in cat.DISK_TYPES:
                res.err(f"{f}.data_disks.{j}.type", f"Disk type must be one of {', '.join(cat.DISK_TYPES)}.")
        norm_vms.append({
            "name": vm.name, "size": vm.size, "image": vm.image, "boot_gb": vm.boot_gb,
            "boot_type": vm.boot_type,
            "data_disks": [{"size_gb": d.size_gb, "type": d.type} for d in vm.data_disks],
        })

    if not req.encryption and not _is_admin(user):
        res.err("encryption", "Only an administrator can create unencrypted disks.")

    # ---- SSH key
    ssh_key, key_err = check_ssh_public_key(req.ssh_public_key)
    if key_err:
        res.err("ssh_public_key", key_err)

    # ---- network
    net = req.network
    wide: list[str] = []
    cidrs: list[str] = []
    if len(net.allowed_cidrs) > MAX_CIDRS:
        res.err("network.allowed_cidrs", f"At most {MAX_CIDRS} CIDR blocks.")
    for raw in net.allowed_cidrs[:MAX_CIDRS]:
        c = _check_cidr(raw, user, res, wide)
        if c:
            cidrs.append(c)
    ports = sorted(set(net.ports))
    for p in ports:
        if p not in cat.ALLOWED_PORTS:
            res.err("network.ports", f"Port {p} cannot be opened. Allowed: {', '.join(map(str, cat.ALLOWED_PORTS))}.")
        elif p not in tpl["allowed_ports"]:
            res.err("network.ports", f"Port {p} is not offered for {tpl['name']}.")
    if net.access == "public":
        if not cidrs and not any(e["field"] == "network.allowed_cidrs" for e in res.errors):
            res.err("network.allowed_cidrs", "Public access needs at least one allowed source CIDR (your IP as a /32 is best).")
        if not ports:
            res.warnings.append("Public access with no open ports: the VMs will have a public IP but nothing can connect.")
    else:
        if "bastion" in req.addons:
            if not cidrs and not any(e["field"] == "network.allowed_cidrs" for e in res.errors):
                res.err("network.allowed_cidrs", "A bastion host needs at least one allowed source CIDR for SSH (your IP as a /32 is best).")
            res.warnings.append("For a private environment the allowed CIDRs apply to the bastion host only; the VMs have no public address.")
        else:
            if net.allowed_cidrs:
                res.warnings.append("Allowed CIDRs are ignored for private environments without a bastion host.")
            cidrs = []
            res.warnings.append("Private environments have no inbound access from the internet. Add a bastion host to reach the VMs.")
        res.warnings.append("Private VMs have no outbound internet access (no NAT gateway), so add-ons that install packages (Docker, monitoring agent, startup scripts) will not complete.")
    if wide:
        res.approvals.append(f"Network exposure to broad range(s) {', '.join(sorted(set(wide)))} needs administrator approval.")
        res.warnings.append(f"Broad source range(s) {', '.join(sorted(set(wide)))} allowed to reach the VMs.")

    # ---- add-ons
    addon_ids = list(dict.fromkeys(req.addons))
    if len(addon_ids) != len(req.addons):
        res.err("addons", "Each add-on can only be selected once.")
    for a in addon_ids:
        addon = catalog.addon(a)
        if addon is None:
            res.err("addons", f"Unknown add-on {a!r}.")
            continue
        if not addon["available"]:
            res.err("addons", f"{addon['name']} is not available: {addon.get('reason', 'not implemented')}")
            continue
        if a not in tpl["allowed_addons"]:
            res.err("addons", f"{addon['name']} cannot be used with {tpl['name']}.")
        if "network:public" in addon["depends_on"] and net.access != "public":
            res.err("addons", f"{addon['name']} needs public network access.")
        for dep in addon["depends_on"]:
            if dep.startswith("port:") and int(dep[5:]) not in ports:
                res.err("addons", f"{addon['name']} needs port {dep[5:]} to be open.")
    if "monitoring_agent" in addon_ids and any(vm.image.startswith("amazon-linux") for vm in vms):
        res.err("addons", "The monitoring agent is only supported on Ubuntu images.")
    scripts = list(dict.fromkeys(req.startup_scripts))
    for sc in scripts:
        if sc not in cat.STARTUP_SCRIPTS:
            res.err("startup_scripts", f"{sc!r} is not in the approved script library.")
    if scripts and "startup_scripts" not in addon_ids:
        res.err("startup_scripts", "Select the 'Approved startup scripts' add-on to use startup scripts.")
    if "startup_scripts" in addon_ids and not scripts:
        res.err("startup_scripts", "Choose at least one approved script or remove the add-on.")

    # ---- tags
    if len(req.tags) > MAX_CUSTOM_TAGS:
        res.err("tags", f"At most {MAX_CUSTOM_TAGS} custom tags.")
    for k, v in req.tags.items():
        if not TAG_KEY_RE.match(k) or k.lower().startswith(RESERVED_TAG_PREFIXES):
            res.err("tags", f"Tag key {k!r} is invalid or reserved (keys cannot start with aws: or lab:).")
        if not TAG_VALUE_RE.match(v):
            res.err("tags", f"Tag value for {k!r} has unsupported characters or is too long.")

    # ---- lifetime
    lt = req.lifetime
    max_minutes = tpl["max_lifetime_minutes"]
    minutes: int | None = None
    fixed_expiry = False
    if (lt.minutes is None) == (lt.expires_at is None):
        res.err("lifetime", "Set exactly one of lifetime.minutes or lifetime.expires_at.")
    elif lt.minutes is not None:
        minutes = lt.minutes
    else:
        try:
            exp = parse_iso(lt.expires_at or "")
            minutes = math.ceil((exp - ctx.now) / 60.0)
            fixed_expiry = True
        except ValueError as e:
            res.err("lifetime.expires_at", f"Invalid timestamp: {e}")
    if minutes is not None:
        if minutes < cat.MIN_LIFETIME_MINUTES:
            res.err("lifetime", f"Lifetime must be at least {cat.MIN_LIFETIME_MINUTES} minutes and in the future.")
        elif minutes > max_minutes:
            res.err("lifetime", f"{tpl['name']} can live at most {max_minutes // 60} hours ({max_minutes // 1440} days).")
    if not lt.auto_destroy:
        if not (_is_admin(user) or user.get("can_disable_autodestroy")):
            res.err("lifetime.auto_destroy", "Disabling automatic destruction needs the 'disable auto-destroy' permission. Ask an administrator.")
        else:
            res.warnings.append(
                "Automatic destruction is OFF: this environment keeps costing money until you destroy it. "
                f"Organisation policy still destroys it after {s.no_autodestroy_retention_minutes // 1440} days."
            )
            res.approvals.append("Disabling automatic destruction needs administrator approval.")

    # ---- demo-only switch
    if req.demo_failure != "none" and req.provider != "demo":
        res.err("demo_failure", "demo_failure only applies to the demo provider.")

    # ---- quotas (hard limits)
    u = ctx.usage
    if u.get("user_envs", 0) + 1 > s.max_active_envs_per_user:
        res.err("quota", f"You already have {u.get('user_envs', 0)} active environments (limit {s.max_active_envs_per_user}). Destroy one first.")
    if u.get("user_vms", 0) + len(vms) > s.max_active_vms_per_user:
        res.err("quota", f"This would exceed your limit of {s.max_active_vms_per_user} active VMs (you have {u.get('user_vms', 0)}).")
    if u.get("project_envs", 0) + 1 > s.max_active_envs_per_project:
        res.err("quota", f"Project {req.project!r} already has {u.get('project_envs', 0)} active environments (limit {s.max_active_envs_per_project}).")

    if res.errors:
        return res

    # ---- normalized plan (only reached when valid)
    assert minutes is not None and ssh_key is not None
    plan: dict[str, Any] = {
        "name": req.name,
        "provider": req.provider,
        "region": req.region,
        "template": req.template,
        "project": req.project,
        "purpose": req.purpose.strip(),
        "owner": user["username"],
        "tags": dict(sorted(req.tags.items())),
        "ssh_public_key": ssh_key,
        "vms": norm_vms,
        "network": {"access": net.access, "allowed_cidrs": cidrs, "ports": ports},
        "encryption": req.encryption,
        "addons": sorted(addon_ids),
        "startup_scripts": sorted(scripts),
        "lifetime_minutes": minutes,
        "fixed_expiry": fixed_expiry,
        "auto_destroy": lt.auto_destroy,
        "notify": lt.notify,
        "demo_failure": req.demo_failure,
    }
    res.plan = plan
    res.estimate = ctx.pricing.estimate(plan)
    est = res.estimate
    if est.total > s.max_env_cost:
        res.err("cost", f"Estimated lifetime cost ${est.total:.2f} exceeds the ${s.max_env_cost:.2f} per-environment limit. Use fewer or smaller VMs, or a shorter lifetime.")
        res.plan = None
        return res
    if not est.complete:
        res.approvals.append("Part of the cost cannot be estimated, so an administrator must approve.")
        res.warnings.append("Part of this environment's cost cannot be estimated; the figure shown is a lower bound.")
    if est.total > s.approval_cost_threshold:
        res.approvals.append(f"Estimated cost ${est.total:.2f} is above ${s.approval_cost_threshold:.2f}, so an administrator must approve.")
    if req.encryption is False:
        res.warnings.append("Disk encryption is OFF.")
    if provider and provider["id"] == "aws":
        res.warnings.append("This will create real, billable AWS resources.")
    if _is_admin(user):
        # Administrators approve their own requests (the audit log records it).
        res.approvals = []
    return res
