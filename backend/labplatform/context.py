"""Wires settings, database, store, pricing and providers together."""
from __future__ import annotations

import secrets

from .catalog import Catalog
from .clock import Clock
from .config import Settings
from .db import Database
from .pricing import Pricing
from .providers.registry import ProviderRegistry
from .security import RateLimiter, hash_password
from .store import Store


class Platform:
    def __init__(self, settings: Settings, clock: Clock | None = None, registry: ProviderRegistry | None = None):
        self.settings = settings
        self.clock = clock or Clock()
        self.db = Database(settings.db_path)
        self.db.init()
        self.store = Store(self.db, self.clock)
        self.pricing = Pricing.load(settings.pricing_file)
        self.providers = registry or ProviderRegistry.build(settings, self.db, self.clock)
        self.limiter = RateLimiter(self.clock)

    def catalog(self, c=None) -> Catalog:
        if c is not None:
            return Catalog(self.settings, self.store.addon_overrides(c))
        with self.db.read() as rc:
            return Catalog(self.settings, self.store.addon_overrides(rc))

    def bootstrap_demo_users(self) -> dict[str, str]:
        """Demo mode only: create a developer and an administrator when no users exist.
        Passwords come from LAB_DEMO_PASSWORD or are random; they are returned once
        so the caller can print them, and are never stored in plain text."""
        if not self.settings.demo_mode:
            return {}
        creds: dict[str, str] = {}
        with self.db.tx() as c:
            if self.store.count_users(c) > 0:
                return {}
            for username, role, can_disable in (("demo-dev", "developer", False), ("demo-admin", "admin", True)):
                pw = self.settings.demo_password or secrets.token_urlsafe(12)
                self.store.create_user(c, username, hash_password(pw), role, can_disable)
                self.store.audit(c, "system", "user.create", username, {"role": role, "bootstrap": "demo"})
                creds[username] = pw
        return creds
