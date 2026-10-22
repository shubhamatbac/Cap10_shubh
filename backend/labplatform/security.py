"""Password hashing, JWT handling, secret redaction and a sliding-window rate limiter."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import threading
import time
from collections import defaultdict, deque

import jwt

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32)
    return "scrypt${}${}${}${}${}".format(
        _SCRYPT_N, _SCRYPT_R, _SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(dk).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# A fixed hash used to equalise timing when the username does not exist.
DUMMY_HASH = hash_password("not-a-real-password")


def issue_token(secret: str, username: str, role: str, ttl_minutes: int, now: float | None = None) -> str:
    now = time.time() if now is None else now
    payload = {"sub": username, "role": role, "iat": int(now), "exp": int(now + ttl_minutes * 60)}
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(secret: str, token: str) -> dict | None:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        return None


# ---------------------------------------------------------------- redaction
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), "[REDACTED AWS KEY ID]"),
    (re.compile(r"(?i)(aws_secret_access_key|secret_access_key|aws_session_token|session_token)(\"?\s*[:=]\s*\"?)[^\s\",]+"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\"?\s*[:=]\s*\"?)[^\s\",;]+"), r"\1\2[REDACTED]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED JWT]"),
]


def redact(text: str) -> str:
    for pattern, repl in _REDACTIONS:
        text = pattern.sub(repl, text)
    return text


# ------------------------------------------------------------- rate limiting
class RateLimiter:
    """In-process sliding window. Adequate for a single API process; use a shared
    store (e.g. Redis) or a gateway limiter if the API is scaled horizontally."""

    def __init__(self, clock=None):
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._now = clock.now if clock else time.time

    def allow(self, key: str, limit: int, window_seconds: int) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        now = self._now()
        with self._lock:
            q = self._hits[key]
            while q and q[0] <= now - window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False, max(1, int(q[0] + window_seconds - now) + 1)
            q.append(now)
            return True, 0
