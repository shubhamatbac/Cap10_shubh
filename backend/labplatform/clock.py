"""Injectable clock so expiry/backoff logic is testable without sleeping."""
from __future__ import annotations

import time
from datetime import datetime, timezone


class Clock:
    def now(self) -> float:
        return time.time()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class FakeClock(Clock):
    def __init__(self, start: float = 1_800_000_000.0):
        self._now = float(start)

    def now(self) -> float:
        return self._now

    def sleep(self, seconds: float) -> None:  # sleeping just advances time
        self._now += seconds

    def advance(self, seconds: float) -> None:
        self._now += seconds


def iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> float:
    """Parse an ISO-8601 timestamp; naive values are rejected to avoid timezone ambiguity."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include a timezone, e.g. 2026-01-01T12:00:00Z")
    return dt.timestamp()
