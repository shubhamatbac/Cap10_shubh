"""AWS adapter: provisions through the reviewed Terraform stack ``terraform/stacks/aws_lab``.

IMPLEMENTED BUT NOT LIVE-TESTED IN THIS REPOSITORY: the unit tests drive this
adapter with a fake Terraform executor and a fake resource inspector. See
docs/cloud-providers.md for the credential and IAM setup required to run it for
real, and the first-run checklist.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence

from ..config import Settings
from ..security import redact
from ..tf.runner import ExecResult, Executor, TerraformRunner, check_plan, clean_env, default_executor
from .base import Provider, ProviderContext, ProviderError, ProvisionResult, build_connection_info, clean_resource_ids

STACK = "aws_lab"
TAG_KEY = "lab:environment_id"
LIVE_INSTANCE_STATES = "pending,running,stopping,stopped,shutting-down"


def build_tfvars(env_id: str, plan: dict[str, Any], expires_at_iso: str, assume_role_arn: str = "") -> dict[str, Any]:
    """Translate the *validated* plan into Terraform variables (plain data only)."""
    addons = set(plan.get("addons", []))
    return {
        "environment_id": env_id,
        "env_name": plan["name"],
        "owner": plan["owner"],
        "project": plan["project"],
        "purpose": plan["purpose"],
        "region": plan["region"],
        "expires_at": expires_at_iso,
        "extra_tags": plan.get("tags", {}),
        "assume_role_arn": assume_role_arn,
        "ssh_public_key": plan["ssh_public_key"],
        "vms": {
            vm["name"]: {
                "size": vm["size"], "image": vm["image"], "boot_gb": vm["boot_gb"], "boot_type": vm["boot_type"],
                "data_disks": vm["data_disks"],
            }
            for vm in plan["vms"]
        },
        "public_access": plan["network"]["access"] == "public",
        "allowed_cidrs": plan["network"]["allowed_cidrs"],
        "ports": plan["network"]["ports"],
        "encryption": plan["encryption"],
        "addons": {
            "docker": "docker" in addons,
            "monitoring_agent": "monitoring_agent" in addons,
            "object_storage": "object_storage" in addons,
            "bastion": "bastion" in addons,
            "load_balancer": "load_balancer" in addons,
        },
        "startup_scripts": plan.get("startup_scripts", []),
    }


class ResourceInspector(Protocol):
    def environment_resources(self, env_id: str, region: str) -> list[str]: ...
    def all_resources(self, regions: Sequence[str]) -> list[dict[str, str]]: ...


class AwsCliInspector:
    """Independent check of what exists in AWS, using the AWS CLI (no Terraform state)."""

    def __init__(self, settings: Settings, executor: Executor | None = None, env_source: Mapping[str, str] | None = None):
        self.s, self.executor, self.env_source = settings, executor or default_executor, env_source

    def _cli(self, region: str, args: Sequence[str]) -> Any:
        argv = [self.s.aws_cli, "--region", region, "--output", "json", *args]
        res = self.executor(argv, Path.cwd(), clean_env(source=self.env_source), 120, lambda _l: None)
        if res.returncode != 0:
            raise ProviderError(f"AWS CLI check failed (exit {res.returncode}): {redact(res.output[-300:])}", retryable=True)
        try:
            return json.loads(res.output or "{}")
        except json.JSONDecodeError as exc:
            raise ProviderError("AWS CLI returned invalid JSON.", retryable=True) from exc

    def environment_resources(self, env_id: str, region: str) -> list[str]:
        found: list[str] = []
        tagged = self._cli(region, ["resourcegroupstaggingapi", "get-resources", "--tag-filters", f"Key={TAG_KEY},Values={env_id}"])
        for item in tagged.get("ResourceTagMappingList", []):
            arn = item.get("ResourceARN", "")
            if ":instance/" in arn:
                continue  # EC2 is checked by state below (terminated instances linger in the tagging API)
            found.append(arn)
        inst = self._cli(region, ["ec2", "describe-instances", "--filters", f"Name=tag:{TAG_KEY},Values={env_id}",
                                  f"Name=instance-state-name,Values={LIVE_INSTANCE_STATES}"])
        for r in inst.get("Reservations", []):
            for i in r.get("Instances", []):
                found.append(f"ec2:{i.get('InstanceId')} ({i.get('State', {}).get('Name')})")
        return found

    def all_resources(self, regions: Sequence[str]) -> list[dict[str, str]]:
        out: list[dict[str, str]] = []
        for region in regions:
            data = self._cli(region, ["resourcegroupstaggingapi", "get-resources", "--tag-filters", f"Key={TAG_KEY}"])
            for item in data.get("ResourceTagMappingList", []):
                arn = item.get("ResourceARN", "")
                tags = {t["Key"]: t["Value"] for t in item.get("Tags", [])}
                if TAG_KEY in tags:
                    out.append({"env_id": tags[TAG_KEY], "resource_id": arn})
        return out


class AwsProvider(Provider):
    id = "aws"

    def __init__(self, settings: Settings, runner: TerraformRunner | None = None, inspector: ResourceInspector | None = None,
                 iso: Callable[[float | None], str | None] | None = None):
        from ..clock import iso as _iso

        self.s = settings
        self.runner = runner or TerraformRunner(settings)
        self.inspector = inspector or AwsCliInspector(settings)
        self._iso = iso or _iso

    def _log(self, ctx: ProviderContext) -> Callable[[str], None]:
        return lambda line: ctx.log(line, "info")

    def provision(self, ctx: ProviderContext) -> ProvisionResult:
        log = self._log(ctx)
        tfvars = build_tfvars(ctx.env_id, ctx.plan, self._iso(ctx.expires_at) or "", self.s.aws_assume_role_arn)
        cwd = self.runner.prepare(ctx.env_id, STACK, tfvars)
        self.runner.init(ctx.env_id, cwd, log)
        self.runner.validate(cwd, log)
        self.runner.plan(cwd, log)
        counts = check_plan(self.runner.show_plan(cwd, log), allow_deletes=False)
        ctx.info(f"Plan checked: {counts['create']} to create, {counts['update']} to update, {counts['delete']} to delete.")
        self.runner.apply_saved_plan(cwd, log)
        outputs = self.runner.outputs(cwd)
        if outputs.get("environment_id") != ctx.env_id:
            raise ProviderError("Terraform outputs do not match this environment; refusing to publish connection details.", retryable=False)
        state = self.runner.state_list(cwd)
        resource_ids = clean_resource_ids(outputs.get("resource_ids")) or clean_resource_ids(state)
        return ProvisionResult(
            connection=build_connection_info(ctx.plan, outputs),
            resource_ids=resource_ids,
            summary=f"{len(ctx.plan['vms'])} VM(s), {len(state)} Terraform resources",
        )

    def destroy(self, ctx: ProviderContext) -> None:
        log = self._log(ctx)
        # Re-prepare so the (possibly fresh) working directory has the reviewed stack and the
        # same variables; existing state in the directory is preserved.
        tfvars = build_tfvars(ctx.env_id, ctx.plan, self._iso(ctx.expires_at) or "", self.s.aws_assume_role_arn)
        cwd = self.runner.prepare(ctx.env_id, STACK, tfvars)
        self.runner.init(ctx.env_id, cwd, log)
        self.runner.assert_state_belongs_to(ctx.env_id, cwd)
        if self.runner.state_list(cwd):
            self.runner.destroy(cwd, log)
        else:
            ctx.info("Terraform state is empty; nothing to destroy through Terraform.")

    def verify_destroyed(self, ctx: ProviderContext) -> list[str]:
        cwd = self.runner.stack_dir(ctx.env_id, STACK)
        leftovers = []
        if cwd.exists():
            leftovers += [f"terraform state: {r}" for r in self.runner.state_list(cwd)]
        leftovers += self.inspector.environment_resources(ctx.env_id, ctx.plan["region"])
        return leftovers

    def list_resources(self) -> list[dict[str, str]]:
        return self.inspector.all_resources(self.s.allowed_regions)
