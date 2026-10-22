"""Command line entry point.

    python -m labplatform serve        API + UI + embedded worker and scheduler
    python -m labplatform worker       worker + scheduler only (separate process)
    python -m labplatform create-user  create a user (password from LAB_NEW_PASSWORD or a prompt)
"""
from __future__ import annotations

import argparse
import getpass
import logging
import os
import signal
import sys
import threading

from .config import Settings
from .context import Platform
from .security import hash_password


def _setup_logging() -> None:
    logging.basicConfig(level=os.environ.get("LAB_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .api import create_app

    settings = Settings.from_env()
    if not settings.demo_mode and args.host not in ("127.0.0.1", "localhost"):
        logging.getLogger("labplatform").warning("Serving beyond localhost: put the API behind TLS (reverse proxy) before exposing it.")
    app = create_app(settings, start_background=not args.no_background)
    uvicorn.run(app, host=args.host, port=args.port, log_level=os.environ.get("LAB_LOG_LEVEL", "info").lower())
    return 0


def cmd_worker(_args: argparse.Namespace) -> int:
    from .api import start_background_tasks

    settings = Settings.from_env()
    platform = Platform(settings)
    stop, threads = threading.Event(), []
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    start_background_tasks(platform, stop, threads)
    logging.getLogger("labplatform").info("Worker and scheduler running (%d worker threads).", settings.worker_threads)
    stop.wait()
    for t in threads:
        t.join(timeout=10)
    return 0


def cmd_create_user(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    platform = Platform(settings)
    password = os.environ.get("LAB_NEW_PASSWORD") or getpass.getpass("Password: ")
    if len(password) < 12:
        print("Password must be at least 12 characters.", file=sys.stderr)
        return 2
    with platform.db.tx() as c:
        platform.store.create_user(c, args.username, hash_password(password), args.role, args.can_disable_autodestroy)
        platform.store.audit(c, "cli", "user.create", args.username, {"role": args.role})
    print(f"Created {args.role} {args.username!r}.")
    return 0


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    parser = argparse.ArgumentParser(prog="labplatform")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("serve")
    p.add_argument("--host", default=os.environ.get("LAB_HOST", "127.0.0.1"))
    p.add_argument("--port", type=int, default=int(os.environ.get("LAB_PORT", "8000")))
    p.add_argument("--no-background", action="store_true", help="do not start the embedded worker/scheduler")
    p.set_defaults(fn=cmd_serve)
    sub.add_parser("worker").set_defaults(fn=cmd_worker)
    p = sub.add_parser("create-user")
    p.add_argument("username")
    p.add_argument("--role", choices=["developer", "admin"], default="developer")
    p.add_argument("--can-disable-autodestroy", action="store_true")
    p.set_defaults(fn=cmd_create_user)
    args = parser.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
