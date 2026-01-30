from __future__ import annotations

from .dns_providers import DNSProvider


class DNSUpdater:
    def __init__(self, provider: DNSProvider) -> None:
        self.provider = provider

    async def upsert_record(
        self, zone: str, name: str, record_type: str, value: str, ttl: int = 60
    ) -> None:
        await self.provider.upsert(zone, name, record_type, value, ttl)

    async def delete_record(self, zone: str, name: str, record_type: str) -> None:
        await self.provider.delete(zone, name, record_type)
