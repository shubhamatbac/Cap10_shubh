"""Safe Terraform execution.

Safety properties enforced here (and covered by tests):

* Terraform is only ever run from *reviewed* stacks in ``terraform/``. User input
  becomes a ``terraform.tfvars.json`` file of plain data; it is never HCL and
  never reaches a shell (argv lists, ``shell=False``).
* One working directory and one state per environment (``<work_root>/<env_id>``),
  with the environment id validated against a strict pattern, so one environment
  can never touch another's state.
* Optional remote state (S3 + lock table) with a per-environment key.
* Provisioning always plans first, saves the plan, inspects it against an
  allowlist of resource types, and applies *that saved plan*.
* Destroy first proves the state belongs to the target environment.
* Subprocesses get a minimal environment (an allowlist of variables); output is
  passed through secret redaction before it is logged.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from ..config import Settings
from ..providers.base import ProviderError
from ..security import redact

ENV_ID_RE = re.compile(r"^env-[0-9a-f]{8}$")

# Environment variables forwarded to Terraform / the AWS CLI. Everything else
# in the server's environment (including LAB_JWT_SECRET) is withheld.
PASSTHROUGH_ENV = (
    "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
    "AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_ROLE_SESSION_NAME", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN",
    "AWS_EC2_METADATA_DISABLED", "AWS_STS_REGIONAL_ENDPOINTS",
)

# Terraform resource types a lab plan is allowed to create or change. A plan that
# touches anything else is rejected before apply.
ALLOWED_RESOURCE_TYPES = frozenset({
    "aws_vpc", "aws_internet_gateway", "aws_subnet", "aws_route_table", "aws_route", "aws_route_table_association",
    "aws_security_group", "aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule",
    "aws_key_pair", "aws_instance", "aws_ebs_volume", "aws_volume_attachment", "aws_eip",
    "aws_lb", "aws_lb_target_group", "aws_lb_target_group_attachment", "aws_lb_listener",
    "aws_s3_bucket", "aws_s3_bucket_public_access_block", "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_ownership_controls", "aws_s3_bucket_versioning",
    "random_id",
})


@dataclass
class ExecResult:
    returncode: int
    output: str


Executor = Callable[[Sequence[str], Path, Mapping[str, str], int, Callable[[str], None]], ExecResult]


def default_executor(argv: Sequence[str], cwd: Path, env: Mapping[str, str], timeout: int, on_line: Callable[[str], None]) -> ExecResult:
    """Run ``argv`` without a shell, streaming merged stdout/stderr line by line."""
    try:
        proc = subprocess.Popen(
            list(argv), cwd=str(cwd), env=dict(env), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, shell=False,
        )
    except FileNotFoundError as exc:
        raise ProviderError(f"Executable not found: {argv[0]!r}. Install it or set the path in the environment configuration.", retryable=False) from exc
    chunks: list[str] = []
    timer = threading.Timer(timeout, proc.kill)
    timer.start()
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip("\n")
            chunks.append(line)
            on_line(line)
        proc.wait()
    finally:
        timer.cancel()
    if proc.returncode in (-9, 137) and timeout:
        chunks.append(f"[killed after {timeout}s timeout]")
    return ExecResult(proc.returncode, "\n".join(chunks))


def clean_env(extra: Mapping[str, str] | None = None, source: Mapping[str, str] | None = None) -> dict[str, str]:
    source = os.environ if source is None else source
    env = {k: source[k] for k in PASSTHROUGH_ENV if k in source}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["TF_IN_AUTOMATION"] = "1"
    env["TF_INPUT"] = "0"
    env["CHECKPOINT_DISABLE"] = "1"
    if extra:
        env.update(extra)
    return env


class PlanRejected(ProviderError):
    def __init__(self, message: str):
        super().__init__(message, retryable=False)


def check_plan(plan_json: dict, *, allow_deletes: bool = False) -> dict[str, int]:
    """Validate ``terraform show -json`` output. Returns create/update/delete counts."""
    counts = {"create": 0, "update": 0, "delete": 0}
    for rc in plan_json.get("resource_changes", []) or []:
        actions = rc.get("change", {}).get("actions", [])
        if actions in (["no-op"], ["read"]):
            continue
        rtype = rc.get("type", "")
        if rtype not in ALLOWED_RESOURCE_TYPES:
            raise PlanRejected(f"Plan rejected: resource type {rtype!r} ({rc.get('address')}) is not on the allowlist.")
        if "delete" in actions:
            counts["delete"] += 1
            if not allow_deletes:
                raise PlanRejected(f"Plan rejected: it would delete or replace {rc.get('address')}.")
        if "create" in actions:
            counts["create"] += 1
        if "update" in actions:
            counts["update"] += 1
    return counts


class TerraformRunner:
    def __init__(self, settings: Settings, executor: Executor | None = None, env_source: Mapping[str, str] | None = None):
        self.s = settings
        self.executor = executor or default_executor
        self.env_source = env_source

    # --------------------------------------------------------- workspace
    def workdir(self, env_id: str) -> Path:
        if not ENV_ID_RE.match(env_id):
            raise ProviderError(f"Refusing to use invalid environment id {env_id!r}.", retryable=False)
        root = self.s.work_root.resolve()
        path = (root / env_id).resolve()
        if root not in path.parents:  # defence in depth against traversal
            raise ProviderError("Refusing a working directory outside the work root.", retryable=False)
        return path

    def stack_dir(self, env_id: str, stack: str) -> Path:
        return self.workdir(env_id) / "stacks" / stack

    def prepare(self, env_id: str, stack: str, tfvars: dict) -> Path:
        """Copy the reviewed stack + modules into this environment's private working
        directory and write its variables. Existing state and provider cache are kept."""
        wd = self.workdir(env_id)
        src_root = self.s.tf_stack_root
        if not (src_root / "stacks" / stack).is_dir():
            raise ProviderError(f"Terraform stack {stack!r} not found under {src_root}.", retryable=False)
        ignore = shutil.ignore_patterns(".terraform", "*.tfstate", "*.tfstate.backup", "tfplan", "terraform.tfvars.json", "backend.tf")
        for part in ("stacks/" + stack, "modules", "scripts"):
            if (src_root / part).exists():
                shutil.copytree(src_root / part, wd / part, dirs_exist_ok=True, ignore=ignore)
        stack_dir = self.stack_dir(env_id, stack)
        tmp = stack_dir / "terraform.tfvars.json.tmp"
        tmp.write_text(json.dumps(tfvars, indent=2, sort_keys=True))
        os.chmod(tmp, 0o600)
        tmp.replace(stack_dir / "terraform.tfvars.json")
        backend = stack_dir / "backend.tf"
        if self.s.tf_backend == "s3":
            backend.write_text('terraform {\n  backend "s3" {}\n}\n')
        elif backend.exists():
            backend.unlink()
        return stack_dir

    def backend_config_args(self, env_id: str) -> list[str]:
        if self.s.tf_backend != "s3":
            return []
        if not (self.s.tf_s3_bucket and self.s.tf_s3_region):
            raise ProviderError("LAB_TF_BACKEND=s3 requires LAB_TF_S3_BUCKET and LAB_TF_S3_REGION.", retryable=False)
        args = [
            f"-backend-config=bucket={self.s.tf_s3_bucket}",
            f"-backend-config=region={self.s.tf_s3_region}",
            f"-backend-config=key=envs/{env_id}/terraform.tfstate",  # isolates state per environment
            "-backend-config=encrypt=true",
        ]
        if self.s.tf_s3_lock_table:
            args.append(f"-backend-config=dynamodb_table={self.s.tf_s3_lock_table}")
        return args

    # --------------------------------------------------------- execution
    def run(self, cwd: Path, args: Sequence[str], log: Callable[[str], None], *, ok_codes: Sequence[int] = (0,)) -> ExecResult:
        argv = [self.s.tf_binary, *args]
        log(f"$ terraform {' '.join(args)}")
        res = self.executor(argv, cwd, clean_env(source=self.env_source), self.s.tf_timeout_seconds, lambda line: log(redact(line)))
        if res.returncode not in ok_codes:
            tail = redact("\n".join(res.output.splitlines()[-8:]))
            raise ProviderError(f"terraform {args[0]} failed (exit {res.returncode}): {tail}", retryable=True)
        return res

    def init(self, env_id: str, cwd: Path, log) -> None:
        args = ["init", "-input=false", "-no-color"]
        if (cwd / ".terraform.lock.hcl").exists():
            args.append("-lockfile=readonly")  # use exactly the committed provider hashes
        else:
            log("WARNING: no .terraform.lock.hcl in the stack; provider versions are not hash-pinned. Commit the lock file (docs/terraform.md).")
        self.run(cwd, [*args, *self.backend_config_args(env_id)], log)

    def validate(self, cwd: Path, log) -> None:
        self.run(cwd, ["validate", "-no-color"], log)

    def plan(self, cwd: Path, log, *, destroy: bool = False) -> None:
        args = ["plan", "-input=false", "-no-color", "-lock-timeout=5m", "-out=tfplan"]
        if destroy:
            args.append("-destroy")
        self.run(cwd, args, log)

    def show_plan(self, cwd: Path, log) -> dict:
        res = self.executor([self.s.tf_binary, "show", "-json", "tfplan"], cwd, clean_env(source=self.env_source), self.s.tf_timeout_seconds, lambda _l: None)
        if res.returncode != 0:
            raise ProviderError(f"terraform show failed (exit {res.returncode}).", retryable=True)
        try:
            return json.loads(res.output)
        except json.JSONDecodeError as exc:
            raise ProviderError("terraform show produced invalid JSON.", retryable=True) from exc

    def apply_saved_plan(self, cwd: Path, log) -> None:
        self.run(cwd, ["apply", "-input=false", "-no-color", "-lock-timeout=5m", "tfplan"], log)

    def destroy(self, cwd: Path, log) -> None:
        self.run(cwd, ["destroy", "-auto-approve", "-input=false", "-no-color", "-lock-timeout=5m"], log)

    def outputs(self, cwd: Path) -> dict:
        res = self.executor([self.s.tf_binary, "output", "-json"], cwd, clean_env(source=self.env_source), 120, lambda _l: None)
        if res.returncode != 0:
            raise ProviderError(f"terraform output failed (exit {res.returncode}).", retryable=True)
        try:
            raw = json.loads(res.output or "{}")
        except json.JSONDecodeError as exc:
            raise ProviderError("terraform output produced invalid JSON.", retryable=True) from exc
        return {k: v.get("value") for k, v in raw.items() if isinstance(v, dict) and not v.get("sensitive")}

    def state_list(self, cwd: Path) -> list[str]:
        res = self.executor([self.s.tf_binary, "state", "list"], cwd, clean_env(source=self.env_source), 120, lambda _l: None)
        text = res.output.strip()
        if res.returncode != 0:
            # An empty/never-initialised state is reported as an error by some versions.
            if "No state file was found" in text or "does not have any" in text:
                return []
            raise ProviderError(f"terraform state list failed (exit {res.returncode}).", retryable=True)
        return [l for l in text.splitlines() if l.strip()]

    def assert_state_belongs_to(self, env_id: str, cwd: Path) -> None:
        """Refuse to destroy unless the state's recorded environment id matches."""
        resources = self.state_list(cwd)
        if not resources:
            return  # nothing in state: nothing to destroy
        outs = self.outputs(cwd)
        found = outs.get("environment_id")
        if found != env_id:
            raise PlanRejected(
                f"Refusing to destroy: state in {cwd.name!r} belongs to environment {found!r}, not {env_id!r}."
            )
