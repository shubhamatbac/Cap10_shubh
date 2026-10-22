"""Runtime configuration, read exclusively from environment variables.

No credentials live in code or in Git. Cloud credentials are never read here:
the Terraform runner passes through only an allowlist of variables from the
server process environment (see ``labplatform.tf.runner``).
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Mapping

REPO_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_REGIONS = ("us-east-1", "us-east-2", "us-west-2", "eu-west-1", "ap-south-1")


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:  # fail fast on a typo instead of silently using a default
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = env.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc


@dataclass(frozen=True)
class Settings:
    # --- general ---
    demo_mode: bool = True
    data_dir: Path = REPO_ROOT / "data"
    jwt_secret: str = ""
    jwt_ttl_minutes: int = 60
    demo_password: str | None = None
    # --- Terraform / AWS ---
    tf_binary: str = "terraform"
    tf_stack_root: Path = REPO_ROOT / "terraform"
    tf_work_root: Path | None = None
    tf_backend: str = "local"  # "local" | "s3"
    tf_s3_bucket: str = ""
    tf_s3_region: str = ""
    tf_s3_lock_table: str = ""
    tf_timeout_seconds: int = 1800
    aws_assume_role_arn: str = ""
    aws_cli: str = "aws"
    enable_aws: bool = False
    allowed_regions: tuple[str, ...] = DEFAULT_REGIONS
    # --- policy / quotas ---
    max_active_envs_per_user: int = 3
    max_active_vms_per_user: int = 8
    max_active_envs_per_project: int = 10
    max_vms_per_env: int = 5
    max_env_cost: float = 25.0  # estimated lifetime cost guardrail (USD)
    approval_cost_threshold: float = 5.0  # above this an admin must approve
    extension_auto_approve_minutes: int = 120
    max_extensions: int = 3
    expiry_warn_minutes: int = 15
    no_autodestroy_retention_minutes: int = 7 * 24 * 60
    failed_cleanup_grace_minutes: int = 10
    approval_ttl_minutes: int = 24 * 60
    # --- jobs ---
    job_max_attempts: int = 3
    backoff_base_seconds: int = 30
    backoff_max_seconds: int = 900
    lease_seconds: int = 3600
    worker_poll_seconds: float = 2.0
    worker_threads: int = 2
    scheduler_interval_seconds: float = 10.0
    max_body_bytes: int = 65536
    # --- rate limits ---
    rate_limit_create_per_hour: int = 10
    rate_limit_login_per_minute: int = 10
    rate_limit_api_per_minute: int = 240
    # --- demo provider timing ---
    demo_step_seconds: float = 2.0
    # --- pricing ---
    pricing_file: Path | None = None
    # --- static frontend ---
    frontend_dir: Path = REPO_ROOT / "frontend"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "labplatform.sqlite3"

    @property
    def work_root(self) -> Path:
        return self.tf_work_root or (self.data_dir / "terraform-work")

    def with_overrides(self, **kw) -> "Settings":
        return replace(self, **kw)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        demo = _bool(env.get("LAB_DEMO_MODE"), True)
        secret = env.get("LAB_JWT_SECRET", "")
        if not secret:
            if not demo:
                raise RuntimeError(
                    "LAB_JWT_SECRET is required when LAB_DEMO_MODE is off. "
                    "Generate one with: python -c 'import secrets;print(secrets.token_urlsafe(48))'"
                )
            # Demo only: an ephemeral secret means sessions end when the server restarts.
            secret = secrets.token_urlsafe(48)
        regions = tuple(
            r.strip() for r in env.get("LAB_ALLOWED_REGIONS", "").split(",") if r.strip()
        ) or DEFAULT_REGIONS
        data_dir = Path(env.get("LAB_DATA_DIR") or (REPO_ROOT / "data"))
        d = cls()
        return cls(
            demo_mode=demo,
            data_dir=data_dir,
            jwt_secret=secret,
            jwt_ttl_minutes=_int(env, "LAB_JWT_TTL_MINUTES", d.jwt_ttl_minutes),
            demo_password=env.get("LAB_DEMO_PASSWORD") or None,
            tf_binary=env.get("LAB_TERRAFORM_BIN", d.tf_binary),
            tf_stack_root=Path(env.get("LAB_TERRAFORM_ROOT") or d.tf_stack_root),
            tf_work_root=Path(env["LAB_TERRAFORM_WORK_ROOT"]) if env.get("LAB_TERRAFORM_WORK_ROOT") else None,
            tf_backend=env.get("LAB_TF_BACKEND", d.tf_backend),
            tf_s3_bucket=env.get("LAB_TF_S3_BUCKET", ""),
            tf_s3_region=env.get("LAB_TF_S3_REGION", ""),
            tf_s3_lock_table=env.get("LAB_TF_S3_LOCK_TABLE", ""),
            tf_timeout_seconds=_int(env, "LAB_TERRAFORM_TIMEOUT_SECONDS", d.tf_timeout_seconds),
            aws_assume_role_arn=env.get("LAB_AWS_ASSUME_ROLE_ARN", ""),
            aws_cli=env.get("LAB_AWS_CLI_BIN", d.aws_cli),
            enable_aws=_bool(env.get("LAB_ENABLE_AWS"), False),
            allowed_regions=regions,
            max_active_envs_per_user=_int(env, "LAB_MAX_ACTIVE_ENVS_PER_USER", d.max_active_envs_per_user),
            max_active_vms_per_user=_int(env, "LAB_MAX_ACTIVE_VMS_PER_USER", d.max_active_vms_per_user),
            max_active_envs_per_project=_int(env, "LAB_MAX_ACTIVE_ENVS_PER_PROJECT", d.max_active_envs_per_project),
            max_vms_per_env=_int(env, "LAB_MAX_VMS_PER_ENV", d.max_vms_per_env),
            max_env_cost=_float(env, "LAB_MAX_ENV_COST", d.max_env_cost),
            approval_cost_threshold=_float(env, "LAB_APPROVAL_COST_THRESHOLD", d.approval_cost_threshold),
            extension_auto_approve_minutes=_int(env, "LAB_EXTENSION_AUTO_APPROVE_MINUTES", d.extension_auto_approve_minutes),
            max_extensions=_int(env, "LAB_MAX_EXTENSIONS", d.max_extensions),
            expiry_warn_minutes=_int(env, "LAB_EXPIRY_WARN_MINUTES", d.expiry_warn_minutes),
            no_autodestroy_retention_minutes=_int(env, "LAB_NO_AUTODESTROY_RETENTION_MINUTES", d.no_autodestroy_retention_minutes),
            failed_cleanup_grace_minutes=_int(env, "LAB_FAILED_CLEANUP_GRACE_MINUTES", d.failed_cleanup_grace_minutes),
            approval_ttl_minutes=_int(env, "LAB_APPROVAL_TTL_MINUTES", d.approval_ttl_minutes),
            job_max_attempts=_int(env, "LAB_JOB_MAX_ATTEMPTS", d.job_max_attempts),
            backoff_base_seconds=_int(env, "LAB_BACKOFF_BASE_SECONDS", d.backoff_base_seconds),
            backoff_max_seconds=_int(env, "LAB_BACKOFF_MAX_SECONDS", d.backoff_max_seconds),
            lease_seconds=_int(env, "LAB_JOB_LEASE_SECONDS", d.lease_seconds),
            worker_poll_seconds=_float(env, "LAB_WORKER_POLL_SECONDS", d.worker_poll_seconds),
            worker_threads=max(1, _int(env, "LAB_WORKER_THREADS", d.worker_threads)),
            max_body_bytes=_int(env, "LAB_MAX_BODY_BYTES", d.max_body_bytes),
            scheduler_interval_seconds=_float(env, "LAB_SCHEDULER_INTERVAL_SECONDS", d.scheduler_interval_seconds),
            rate_limit_create_per_hour=_int(env, "LAB_RATE_LIMIT_CREATE_PER_HOUR", d.rate_limit_create_per_hour),
            rate_limit_login_per_minute=_int(env, "LAB_RATE_LIMIT_LOGIN_PER_MINUTE", d.rate_limit_login_per_minute),
            rate_limit_api_per_minute=_int(env, "LAB_RATE_LIMIT_API_PER_MINUTE", d.rate_limit_api_per_minute),
            demo_step_seconds=_float(env, "LAB_DEMO_STEP_SECONDS", d.demo_step_seconds),
            pricing_file=Path(env["LAB_PRICING_FILE"]) if env.get("LAB_PRICING_FILE") else None,
            frontend_dir=Path(env.get("LAB_FRONTEND_DIR") or d.frontend_dir),
        )
