"""Environment lifecycle state machine.

    Pending -> Provisioning -> Running -> Expiring -> Destroying -> Destroyed
                    |             ^  \\______^            |
                    v             |                       v
                  Failed ---------+                 CleanupFailed

Every state change goes through ``assert_transition`` and a guarded SQL
``UPDATE ... WHERE state IN (...)`` so concurrent workers cannot corrupt state.
"""
from __future__ import annotations

PENDING = "Pending"
PROVISIONING = "Provisioning"
RUNNING = "Running"
EXPIRING = "Expiring"
DESTROYING = "Destroying"
DESTROYED = "Destroyed"
FAILED = "Failed"
CLEANUP_FAILED = "CleanupFailed"

ALL_STATES = (PENDING, PROVISIONING, RUNNING, EXPIRING, DESTROYING, DESTROYED, FAILED, CLEANUP_FAILED)

TRANSITIONS: dict[str, frozenset[str]] = {
    # Pending -> Destroyed: cancelled or rejected before anything was created.
    PENDING: frozenset({PROVISIONING, DESTROYED}),
    PROVISIONING: frozenset({RUNNING, FAILED}),
    RUNNING: frozenset({EXPIRING, DESTROYING}),
    EXPIRING: frozenset({RUNNING, DESTROYING}),  # Expiring -> Running when extended
    DESTROYING: frozenset({DESTROYED, CLEANUP_FAILED}),
    FAILED: frozenset({PROVISIONING, DESTROYING}),
    CLEANUP_FAILED: frozenset({DESTROYING}),
    DESTROYED: frozenset(),
}

# Anything not Destroyed counts against quotas.
ACTIVE_STATES = tuple(s for s in ALL_STATES if s != DESTROYED)
# Resources may exist (and cost money) in these states.
POTENTIALLY_BILLABLE = (PROVISIONING, RUNNING, EXPIRING, DESTROYING, FAILED, CLEANUP_FAILED)
# States from which a destroy may be started.
DESTROYABLE = (PENDING, RUNNING, EXPIRING, FAILED, CLEANUP_FAILED)


class InvalidTransition(Exception):
    pass


def can_transition(src: str, dst: str) -> bool:
    return dst in TRANSITIONS.get(src, frozenset())


def assert_transition(src: str, dst: str) -> None:
    if not can_transition(src, dst):
        raise InvalidTransition(f"Cannot move an environment from {src} to {dst}.")


def sources_for(dst: str) -> tuple[str, ...]:
    """States from which ``dst`` is a legal next state."""
    return tuple(s for s, nxt in TRANSITIONS.items() if dst in nxt)


def is_potentially_billable(state: str) -> bool:
    return state in POTENTIALLY_BILLABLE
