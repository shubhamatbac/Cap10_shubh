"""HTTP API (Starlette) and static frontend hosting.

Every route goes through one wrapper that authenticates the bearer token,
re-loads the user (so role changes and disabling apply immediately), enforces
the role, applies rate limits and turns ``ServiceError`` into a uniform JSON
error body. Business rules live in ``service.py``; nothing here decides policy.
"""
from __future__ import annotations

import json
import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable

from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse, Response
from starlette.routing import Route
from starlette.staticfiles import StaticFiles

from . import __version__
from .config import Settings
from .context import Platform
from .scheduler import Scheduler
from .security import decode_token, issue_token
from .service import Service, ServiceError
from .worker import Worker

log = logging.getLogger("labplatform.api")

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)


class SecurityHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response


def _error(status: int, code: str, message: str, details: Any = None, headers: dict[str, str] | None = None) -> JSONResponse:
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    if details is not None:
        body["error"]["details"] = details
    return JSONResponse(body, status_code=status, headers=headers)


async def _read_json(request: Request, limit: int) -> Any:
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit:
        raise ServiceError(413, "too_large", "Request body is too large.")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise ServiceError(413, "too_large", "Request body is too large.")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ServiceError(400, "bad_json", "The request body is not valid JSON.") from None


def _int_param(request: Request, name: str, default: int, lo: int, hi: int) -> int:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    try:
        return max(lo, min(hi, int(raw)))
    except ValueError:
        raise ServiceError(400, "bad_parameter", f"{name} must be an integer.") from None


def create_app(settings: Settings | None = None, platform: Platform | None = None, *, start_background: bool = True) -> Starlette:
    settings = settings or (platform.settings if platform else Settings.from_env())
    platform = platform or Platform(settings)
    svc = Service(platform)
    routes: list[Route] = []

    def route(path: str, methods: list[str], *, public: bool = False, admin: bool = False, body: bool = False,
              limit_key: str | None = None) -> Callable:
        """Register ``fn(user, request, data) -> (payload, status)`` or just ``payload``."""

        def deco(fn: Callable) -> Callable:
            async def handler(request: Request) -> Response:
                try:
                    user = None
                    if not public:
                        user = await run_in_threadpool(_authenticate, request)
                        if admin and user["role"] != "admin":
                            raise ServiceError(403, "forbidden", "Administrator access is required.")
                        ok, retry = platform.limiter.allow(f"api:{user['id']}", settings.rate_limit_api_per_minute, 60)
                        if not ok:
                            raise ServiceError(429, "rate_limited", f"Too many requests. Retry in {retry}s.", {"retry_after": retry})
                    data = await _read_json(request, settings.max_body_bytes) if body else None
                    result = await run_in_threadpool(fn, user, request, data)
                    payload, status = result if isinstance(result, tuple) else (result, 200)
                    if isinstance(payload, Response):
                        return payload
                    return JSONResponse(payload, status_code=status)
                except ServiceError as exc:
                    headers = {"Retry-After": str(exc.details["retry_after"])} if exc.code == "rate_limited" and exc.details else None
                    if exc.status == 401:
                        headers = {"WWW-Authenticate": "Bearer"}
                    return _error(exc.status, exc.code, exc.message, exc.details if exc.code != "rate_limited" else None, headers)
                except Exception:  # noqa: BLE001 - never leak internals
                    log.exception("unhandled error on %s %s", request.method, request.url.path)
                    return _error(500, "internal_error", "An unexpected error occurred.")

            routes.append(Route(path, handler, methods=methods))
            return fn

        return deco

    def _authenticate(request: Request) -> dict[str, Any]:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise ServiceError(401, "unauthorized", "Sign in required.")
        claims = decode_token(settings.jwt_secret, header[7:].strip())
        user = svc.user_from_claims(claims) if claims else None
        if not user:
            raise ServiceError(401, "unauthorized", "Your session is invalid or has expired. Sign in again.")
        return user

    def public_user(u: dict[str, Any]) -> dict[str, Any]:
        return {"username": u["username"], "role": u["role"], "can_disable_autodestroy": bool(u["can_disable_autodestroy"])}

    def env_id(request: Request) -> str:
        return request.path_params["env_id"]

    # ------------------------------------------------------------------ public
    @route("/api/health", ["GET"], public=True)
    def health(_u, _r, _d):
        with platform.db.read() as c:
            c.execute("SELECT 1").fetchone()
        return {"status": "ok", "version": __version__, "demo_mode": settings.demo_mode, "providers": platform.providers.ids()}

    @route("/api/auth/login", ["POST"], public=True, body=True)
    def login(_u, request, data):
        ip = request.client.host if request.client else "unknown"
        username = str((data or {}).get("username", ""))[:64]
        password = str((data or {}).get("password", ""))[:256]
        for key in (f"login-ip:{ip}", f"login-user:{username.lower()}"):
            ok, retry = platform.limiter.allow(key, settings.rate_limit_login_per_minute, 60)
            if not ok:
                raise ServiceError(429, "rate_limited", f"Too many sign-in attempts. Retry in {retry}s.", {"retry_after": retry})
        user = svc.authenticate(username, password)
        if not user:
            raise ServiceError(401, "invalid_credentials", "Invalid username or password.")
        token = issue_token(settings.jwt_secret, user["username"], user["role"], settings.jwt_ttl_minutes, platform.clock.now())
        return {"token": token, "expires_in": settings.jwt_ttl_minutes * 60, "user": public_user(user)}

    # -------------------------------------------------------------- session/meta
    @route("/api/auth/me", ["GET"])
    def me(user, _r, _d):
        return {"user": public_user(user), "demo_mode": settings.demo_mode}

    @route("/api/catalog", ["GET"])
    def catalog(_u, _r, _d):
        return platform.catalog().as_dict()

    # ------------------------------------------------------------- environments
    @route("/api/environments/preview", ["POST"], body=True)
    def preview(user, _r, data):
        return svc.preview(user, data)

    @route("/api/environments", ["POST"], body=True)
    def create(user, request, data):
        ok, retry = platform.limiter.allow(f"create:{user['id']}", settings.rate_limit_create_per_hour, 3600)
        if not ok:
            raise ServiceError(429, "rate_limited", f"Environment creation limit reached. Retry in {retry}s.", {"retry_after": retry})
        env, created = svc.create_environment(user, data, request.headers.get("idempotency-key"))
        return env, 201 if created else 200

    @route("/api/environments", ["GET"])
    def list_envs(user, request, _d):
        all_users = request.query_params.get("all") == "1"
        include_destroyed = request.query_params.get("destroyed", "1") != "0"
        return {"environments": svc.list_environments(user, all_users, include_destroyed)}

    @route("/api/environments/{env_id}", ["GET"])
    def get_env(user, request, _d):
        return svc.get_environment(user, env_id(request))

    @route("/api/environments/{env_id}/logs", ["GET"])
    def logs(user, request, _d):
        return {"logs": svc.get_logs(user, env_id(request), _int_param(request, "after", 0, 0, 2**62))}

    @route("/api/environments/{env_id}/connection", ["GET"])
    def connection(user, request, _d):
        return svc.get_connection(user, env_id(request))

    @route("/api/environments/{env_id}/jobs", ["GET"])
    def jobs(user, request, _d):
        return {"jobs": svc.get_jobs(user, env_id(request))}

    @route("/api/environments/{env_id}/destroy", ["POST"])
    def destroy(user, request, _d):
        return svc.destroy_environment(user, env_id(request)), 202

    @route("/api/environments/{env_id}/retry", ["POST"])
    def retry(user, request, _d):
        return svc.retry_provision(user, env_id(request)), 202

    @route("/api/environments/{env_id}/extend", ["POST"], body=True)
    def extend(user, request, data):
        data = data if isinstance(data, dict) else {}
        minutes = data.get("minutes")
        if not isinstance(minutes, int) or isinstance(minutes, bool):
            raise ServiceError(422, "validation_failed", "minutes must be a whole number.")
        return svc.request_extension(user, env_id(request), minutes, str(data.get("reason", "")))

    @route("/api/dashboard", ["GET"])
    def dashboard(user, _r, _d):
        return svc.dashboard(user)

    # -------------------------------------------------------------------- admin
    @route("/api/admin/overview", ["GET"], admin=True)
    def admin_overview(_u, _r, _d):
        return svc.admin_overview()

    @route("/api/admin/audit", ["GET"], admin=True)
    def audit(_u, request, _d):
        return {"audit": svc.list_audit(_int_param(request, "limit", 200, 1, 500), request.query_params.get("target"))}

    @route("/api/admin/environments/{env_id}/approve", ["POST"], admin=True)
    def approve(user, request, _d):
        return svc.approve_environment(user, env_id(request), True)

    @route("/api/admin/environments/{env_id}/reject", ["POST"], admin=True)
    def reject(user, request, _d):
        return svc.approve_environment(user, env_id(request), False)

    @route("/api/admin/environments/{env_id}/retry-cleanup", ["POST"], admin=True)
    def retry_cleanup(user, request, _d):
        return svc.retry_cleanup(user, env_id(request)), 202

    @route("/api/admin/extensions/{ext_id:int}/approve", ["POST"], admin=True)
    def ext_approve(user, request, _d):
        return svc.decide_extension(user, request.path_params["ext_id"], True)

    @route("/api/admin/extensions/{ext_id:int}/reject", ["POST"], admin=True)
    def ext_reject(user, request, _d):
        return svc.decide_extension(user, request.path_params["ext_id"], False)

    @route("/api/admin/alerts/{alert_id:int}/ack", ["POST"], admin=True)
    def alert_ack(user, request, _d):
        svc.acknowledge_alert(user, request.path_params["alert_id"])
        return {"ok": True}

    @route("/api/admin/addons/{addon_id}", ["POST"], admin=True, body=True)
    def addon_toggle(user, request, data):
        enabled = (data or {}).get("enabled")
        if not isinstance(enabled, bool):
            raise ServiceError(422, "validation_failed", "enabled must be true or false.")
        return {"addons": svc.set_addon_enabled(user, request.path_params["addon_id"], enabled)}

    @route("/api/admin/reconcile", ["POST"], admin=True)
    def reconcile(user, _r, _d):
        return svc.reconcile(user)

    # ---------------------------------------------------------------- frontend
    async def api_not_found(request: Request) -> Response:
        return _error(404, "not_found", "No such API endpoint.")

    routes.append(Route("/api/{rest:path}", api_not_found, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]))

    frontend = Path(settings.frontend_dir)
    if frontend.is_dir():
        async def index(_request: Request) -> Response:
            return FileResponse(frontend / "index.html", headers={"Cache-Control": "no-cache"})

        routes.append(Route("/", index, methods=["GET"]))
        from starlette.routing import Mount
        routes.append(Mount("/", app=StaticFiles(directory=str(frontend)), name="static"))

    stop = threading.Event()
    threads: list[threading.Thread] = []

    @asynccontextmanager
    async def lifespan(_app: Starlette):
        creds = platform.bootstrap_demo_users()
        if creds:
            log.warning("Demo users created (shown once): %s", ", ".join(f"{u} / {p}" for u, p in creds.items()))
        if start_background:
            start_background_tasks(platform, stop, threads)
        try:
            yield
        finally:
            stop.set()
            for t in threads:
                t.join(timeout=5)

    app = Starlette(routes=routes, lifespan=lifespan, middleware=[])
    app.add_middleware(SecurityHeaders)
    app.state.platform = platform
    app.state.service = svc
    return app


def start_background_tasks(platform: Platform, stop: threading.Event, threads: list[threading.Thread]) -> None:
    """Start the durable worker threads and the expiry scheduler. They read all state
    from the database, so they behave identically when run in a separate process
    (``python -m labplatform worker``)."""
    sched = Scheduler(platform)
    t = threading.Thread(target=sched.run_forever, args=(stop,), name="lab-scheduler", daemon=True)
    t.start()
    threads.append(t)
    for i in range(platform.settings.worker_threads):
        w = Worker(platform)
        t = threading.Thread(target=w.run_forever, args=(stop,), name=f"lab-worker-{i}", daemon=True)
        t.start()
        threads.append(t)
