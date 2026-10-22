"""Provider registry. Register new adapters here."""
from __future__ import annotations

from ..clock import Clock
from ..config import Settings
from ..db import Database
from .aws import AwsProvider
from .base import Provider, ProviderError
from .demo import DemoProvider


class ProviderRegistry:
    def __init__(self, providers: dict[str, Provider]):
        self._providers = providers

    @classmethod
    def build(cls, settings: Settings, db: Database, clock: Clock) -> "ProviderRegistry":
        providers: dict[str, Provider] = {}
        if settings.demo_mode:
            providers["demo"] = DemoProvider(db, clock, settings.demo_step_seconds, settings.job_max_attempts)
        if settings.enable_aws:
            providers["aws"] = AwsProvider(settings)
        return cls(providers)

    def get(self, provider_id: str) -> Provider:
        try:
            return self._providers[provider_id]
        except KeyError:
            raise ProviderError(f"Provider {provider_id!r} is not enabled on this server.", retryable=False) from None

    def ids(self) -> list[str]:
        return sorted(self._providers)
