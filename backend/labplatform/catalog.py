"""Static catalog: providers, templates, images, sizes, add-ons and policy defaults.

Everything a user can select is declared here and validated server-side. Nothing
in a request is ever interpreted as Terraform code or a shell command: requests
can only reference identifiers from this catalog.

Items that are *not* implemented are listed with ``available: False`` and a
reason, so the UI can show them honestly instead of hiding or faking them.
"""
from __future__ import annotations

from typing import Any

from .config import Settings

HOUR = 60
DAY = 24 * HOUR

LIFETIME_PRESETS = [
    {"minutes": 30, "label": "30 minutes"},
    {"minutes": 1 * HOUR, "label": "1 hour"},
    {"minutes": 4 * HOUR, "label": "4 hours"},
    {"minutes": 8 * HOUR, "label": "8 hours"},
    {"minutes": 24 * HOUR, "label": "24 hours"},
    {"minutes": 3 * DAY, "label": "3 days"},
    {"minutes": 7 * DAY, "label": "7 days"},
]
MIN_LIFETIME_MINUTES = 15

# Instance sizes. vCPU / memory are *derived* from the size, never free-form, so
# only combinations the provider really offers can be requested.
SIZES: dict[str, dict[str, Any]] = {
    "t3.micro": {"vcpu": 2, "memory_gib": 1},
    "t3.small": {"vcpu": 2, "memory_gib": 2},
    "t3.medium": {"vcpu": 2, "memory_gib": 4},
    "t3.large": {"vcpu": 2, "memory_gib": 8},
    "t3.xlarge": {"vcpu": 4, "memory_gib": 16},
}

# Approved images. AWS AMIs are resolved at apply time from public SSM
# parameters (see terraform/modules/aws_compute), so no AMI IDs are hardcoded.
IMAGES: dict[str, dict[str, Any]] = {
    "ubuntu-24.04": {"label": "Ubuntu Server 24.04 LTS", "os": "linux", "ssh_user": "ubuntu"},
    "ubuntu-22.04": {"label": "Ubuntu Server 22.04 LTS", "os": "linux", "ssh_user": "ubuntu"},
    "amazon-linux-2023": {"label": "Amazon Linux 2023", "os": "linux", "ssh_user": "ec2-user"},
}

DISK_TYPES = ("gp3", "gp2")
BOOT_GB_RANGE = (8, 100)
DATA_GB_RANGE = (1, 500)
MAX_DATA_DISKS_PER_VM = 3

# Ports that may ever be opened. Everything else is rejected.
ALLOWED_PORTS = {22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP (alternate)"}

# Approved bootstrap scripts. Users pick an ID; script bodies live in
# terraform/scripts/ and are reviewed code, never user supplied text.
STARTUP_SCRIPTS = {
    "nginx-hello": {"label": "Nginx with a hello page", "description": "Installs nginx and serves a static test page on port 80."},
    "swap-1g": {"label": "1 GiB swap file", "description": "Creates and enables a 1 GiB swap file."},
}

PROVIDERS: list[dict[str, Any]] = [
    {"id": "demo", "name": "Demo (simulated)", "kind": "simulated",
     "note": "Simulates the full lifecycle without creating any cloud resources or costs."},
    {"id": "aws", "name": "Amazon Web Services", "kind": "terraform",
     "note": "Implemented through Terraform. Not exercised against a live account in this repository's CI; see docs/cloud-providers.md."},
    {"id": "azure", "name": "Microsoft Azure", "kind": "planned", "note": "Not implemented. Add an adapter under labplatform/providers."},
    {"id": "gcp", "name": "Google Cloud Platform", "kind": "planned", "note": "Not implemented. Add an adapter under labplatform/providers."},
    {"id": "oci", "name": "Oracle Cloud Infrastructure", "kind": "planned", "note": "Not implemented. Add an adapter under labplatform/providers."},
    {"id": "proxmox", "name": "Proxmox (local virtualization)", "kind": "planned", "note": "Not implemented. Add an adapter under labplatform/providers."},
]

_LINUX_SIZES = ["t3.micro", "t3.small", "t3.medium", "t3.large", "t3.xlarge"]
_COMMON_ADDONS = ["docker", "monitoring_agent", "object_storage", "bastion", "startup_scripts"]

TEMPLATES: list[dict[str, Any]] = [
    {"id": "linux_vm", "name": "Single Linux VM", "description": "One Linux server for quick experiments.",
     "available": True, "min_vms": 1, "max_vms": 1, "default_vm_count": 1,
     "default_size": "t3.micro", "allowed_sizes": _LINUX_SIZES, "default_image": "ubuntu-24.04",
     "default_boot_gb": 20, "default_ports": [22], "allowed_ports": [22, 80, 443],
     "allowed_addons": ["docker", "monitoring_agent", "object_storage", "startup_scripts"], "default_addons": [],
     "default_lifetime_minutes": 4 * HOUR, "max_lifetime_minutes": 7 * DAY},
    {"id": "multi_vm", "name": "Multi-VM environment", "description": "Two to five Linux servers on one private network.",
     "available": True, "min_vms": 2, "max_vms": 5, "default_vm_count": 2,
     "default_size": "t3.micro", "allowed_sizes": _LINUX_SIZES, "default_image": "ubuntu-24.04",
     "default_boot_gb": 20, "default_ports": [22], "allowed_ports": [22, 80, 443],
     "allowed_addons": _COMMON_ADDONS, "default_addons": [],
     "default_lifetime_minutes": 8 * HOUR, "max_lifetime_minutes": 3 * DAY},
    {"id": "web_test", "name": "Web application test environment", "description": "One to three web servers, optionally behind a load balancer.",
     "available": True, "min_vms": 1, "max_vms": 3, "default_vm_count": 1,
     "default_size": "t3.small", "allowed_sizes": _LINUX_SIZES, "default_image": "ubuntu-24.04",
     "default_boot_gb": 20, "default_ports": [22, 80], "allowed_ports": [22, 80, 443, 8080],
     "allowed_addons": _COMMON_ADDONS + ["load_balancer"], "default_addons": [],
     "default_lifetime_minutes": 8 * HOUR, "max_lifetime_minutes": 3 * DAY},
    {"id": "docker_host", "name": "Docker host", "description": "A Linux server with Docker Engine installed.",
     "available": True, "min_vms": 1, "max_vms": 2, "default_vm_count": 1,
     "default_size": "t3.medium", "allowed_sizes": _LINUX_SIZES[1:], "default_image": "ubuntu-24.04",
     "default_boot_gb": 30, "default_ports": [22], "allowed_ports": [22, 80, 443, 8080],
     "allowed_addons": ["docker", "monitoring_agent", "object_storage", "bastion", "startup_scripts"], "default_addons": ["docker"],
     "default_lifetime_minutes": 8 * HOUR, "max_lifetime_minutes": 3 * DAY},
    {"id": "monitoring_lab", "name": "Monitoring lab", "description": "Two or three servers with a metrics agent for practising dashboards and alerts.",
     "available": True, "min_vms": 2, "max_vms": 3, "default_vm_count": 2,
     "default_size": "t3.small", "allowed_sizes": _LINUX_SIZES[1:], "default_image": "ubuntu-24.04",
     "default_boot_gb": 20, "default_ports": [22], "allowed_ports": [22, 80, 443],
     "allowed_addons": ["docker", "monitoring_agent", "bastion", "startup_scripts"], "default_addons": ["monitoring_agent"],
     "default_lifetime_minutes": 8 * HOUR, "max_lifetime_minutes": 3 * DAY},
    {"id": "devops_practice", "name": "DevOps practice environment", "description": "Two to four servers with Docker and a bastion host option for pipeline and automation practice.",
     "available": True, "min_vms": 2, "max_vms": 4, "default_vm_count": 2,
     "default_size": "t3.small", "allowed_sizes": _LINUX_SIZES[1:], "default_image": "ubuntu-24.04",
     "default_boot_gb": 20, "default_ports": [22], "allowed_ports": [22, 80, 443, 8080],
     "allowed_addons": _COMMON_ADDONS, "default_addons": ["docker"],
     "default_lifetime_minutes": 1 * DAY, "max_lifetime_minutes": 3 * DAY},
    {"id": "windows_vm", "name": "Single Windows VM", "description": "One Windows Server instance.",
     "available": False, "reason": "Not implemented: needs an approved Windows image and a credential hand-off design (see docs/architecture.md)."},
    {"id": "kubernetes_dev", "name": "Kubernetes development cluster", "description": "A small Kubernetes cluster.",
     "available": False, "reason": "Not implemented: needs a managed-cluster or kubeadm module."},
    {"id": "database_test", "name": "Database test environment", "description": "A managed database for testing.",
     "available": False, "reason": "Not implemented: managed database add-on is not built yet."},
]

# Add-ons. Each declares dependencies, permissions, cost and destruction behaviour.
ADDONS: list[dict[str, Any]] = [
    {"id": "docker", "name": "Docker Engine", "available": True,
     "description": "Installs Docker Engine on every VM through cloud-init.",
     "depends_on": [], "permissions": [], "cost": "No extra infrastructure cost.",
     "destruction": "Removed with the VMs."},
    {"id": "monitoring_agent", "name": "Monitoring agent", "available": True,
     "description": "Installs the Prometheus node exporter on every VM (port 9100, private network only).",
     "depends_on": [], "permissions": [], "cost": "No extra infrastructure cost.",
     "destruction": "Removed with the VMs."},
    {"id": "object_storage", "name": "Object storage bucket", "available": True,
     "description": "Creates one private, encrypted S3 bucket for the environment.",
     "depends_on": [], "permissions": ["storage:create"], "cost": "Usage based; not included in the estimate.",
     "destruction": "Bucket is emptied and deleted with the environment (all objects are lost)."},
    {"id": "bastion", "name": "Bastion host", "available": True,
     "description": "Adds one small SSH jump host. VMs accept SSH from the bastion.",
     "depends_on": [], "permissions": ["network:public-ip"], "cost": "One t3.micro plus one public IPv4 address.",
     "destruction": "Removed with the environment."},
    {"id": "load_balancer", "name": "Application load balancer", "available": True,
     "description": "Puts an HTTP load balancer in front of the VMs. Requires port 80 and public access.",
     "depends_on": ["network:public", "port:80"], "permissions": ["network:public-ip"],
     "cost": "Hourly charge is estimated; usage-based charges are not.",
     "destruction": "Removed with the environment."},
    {"id": "startup_scripts", "name": "Approved startup scripts", "available": True,
     "description": "Runs scripts from the reviewed library at first boot. Choose scripts below.",
     "depends_on": [], "permissions": ["scripts:run-approved"], "cost": "No extra infrastructure cost.",
     "destruction": "Removed with the VMs."},
    {"id": "managed_database", "name": "Managed database", "available": False,
     "reason": "Not implemented.", "description": "A managed relational database.",
     "depends_on": [], "permissions": [], "cost": "", "destruction": ""},
    {"id": "dns", "name": "DNS records", "available": False,
     "reason": "Not implemented.", "description": "Friendly DNS names for VMs.",
     "depends_on": [], "permissions": [], "cost": "", "destruction": ""},
    {"id": "logging", "name": "Central logging", "available": False,
     "reason": "Not implemented.", "description": "Ship logs to a central store.",
     "depends_on": [], "permissions": [], "cost": "", "destruction": ""},
    {"id": "ansible", "name": "Ansible configuration", "available": False,
     "reason": "Not implemented: arbitrary playbooks would be arbitrary code execution; needs a reviewed playbook library.",
     "description": "Apply an approved Ansible playbook.", "depends_on": [], "permissions": [], "cost": "", "destruction": ""},
    {"id": "kubernetes", "name": "Kubernetes", "available": False,
     "reason": "Not implemented.", "description": "Kubernetes on the VMs.",
     "depends_on": [], "permissions": [], "cost": "", "destruction": ""},
    {"id": "snapshots", "name": "Snapshots and backups", "available": False,
     "reason": "Not implemented. Lab environments are temporary; take your own copies of data you need.",
     "description": "Scheduled disk snapshots.", "depends_on": [], "permissions": [], "cost": "", "destruction": ""},
]


class Catalog:
    """Catalog resolved against current settings and admin add-on toggles."""

    def __init__(self, settings: Settings, addon_overrides: dict[str, bool] | None = None):
        self.settings = settings
        self.addon_overrides = addon_overrides or {}

    # providers ---------------------------------------------------------
    def providers(self) -> list[dict[str, Any]]:
        out = []
        for p in PROVIDERS:
            item = dict(p)
            if p["id"] == "demo":
                item["available"] = self.settings.demo_mode
                if not item["available"]:
                    item["reason"] = "Demo mode is off (LAB_DEMO_MODE)."
            elif p["id"] == "aws":
                item["available"] = self.settings.enable_aws
                if not item["available"]:
                    item["reason"] = "Disabled. Set LAB_ENABLE_AWS=true after configuring credentials (docs/cloud-providers.md)."
            else:
                item["available"] = False
                item["reason"] = p["note"]
            out.append(item)
        return out

    def provider(self, provider_id: str) -> dict[str, Any] | None:
        return next((p for p in self.providers() if p["id"] == provider_id), None)

    def sizes(self) -> dict[str, dict[str, Any]]:
        return SIZES

    def images(self) -> dict[str, dict[str, Any]]:
        return IMAGES

    # templates -----------------------------------------------------------
    def templates(self) -> list[dict[str, Any]]:
        return [dict(t) for t in TEMPLATES]

    def template(self, template_id: str) -> dict[str, Any] | None:
        return next((dict(t) for t in TEMPLATES if t["id"] == template_id), None)

    # add-ons ---------------------------------------------------------
    def addons(self) -> list[dict[str, Any]]:
        out = []
        for a in ADDONS:
            item = dict(a)
            enabled = self.addon_overrides.get(a["id"], True)
            item["enabled"] = enabled
            if a["available"] and not enabled:
                item["available"] = False
                item["reason"] = "Disabled by an administrator."
            out.append(item)
        return out

    def addon(self, addon_id: str) -> dict[str, Any] | None:
        return next((a for a in self.addons() if a["id"] == addon_id), None)

    def as_dict(self) -> dict[str, Any]:
        return {
            "providers": self.providers(),
            "templates": self.templates(),
            "images": self.images(),
            "sizes": self.sizes(),
            "addons": self.addons(),
            "startup_scripts": STARTUP_SCRIPTS,
            "disk_types": list(DISK_TYPES),
            "boot_gb_range": list(BOOT_GB_RANGE),
            "data_gb_range": list(DATA_GB_RANGE),
            "max_data_disks_per_vm": MAX_DATA_DISKS_PER_VM,
            "allowed_ports": {str(k): v for k, v in ALLOWED_PORTS.items()},
            "lifetime_presets": LIFETIME_PRESETS,
            "min_lifetime_minutes": MIN_LIFETIME_MINUTES,
            "regions": list(self.settings.allowed_regions),
            "limits": {
                "max_vms_per_env": self.settings.max_vms_per_env,
                "max_active_envs_per_user": self.settings.max_active_envs_per_user,
                "max_active_vms_per_user": self.settings.max_active_vms_per_user,
                "max_env_cost": self.settings.max_env_cost,
                "approval_cost_threshold": self.settings.approval_cost_threshold,
                "extension_auto_approve_minutes": self.settings.extension_auto_approve_minutes,
            },
            "demo_mode": self.settings.demo_mode,
        }
