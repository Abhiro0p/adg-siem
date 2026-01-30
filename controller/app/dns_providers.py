from __future__ import annotations

import asyncio
import logging
import re

import dns.name
import dns.update
import dns.query
import dns.tsigkeyring
import httpx

logger = logging.getLogger("adg.dns")

# DNS name/value sanitisation
_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-\.]+$")
_SAFE_VALUE_RE = re.compile(r"^[a-zA-Z0-9_\-\.\:]+$")


def _sanitise(name: str, value: str) -> tuple[str, str]:
    if not _SAFE_NAME_RE.match(name):
        raise ValueError(f"Invalid DNS name: {name!r}")
    if not _SAFE_VALUE_RE.match(value):
        raise ValueError(f"Invalid DNS record value: {value!r}")
    return name, value


class DNSProvider:
    async def upsert(self, zone: str, name: str, record_type: str, value: str, ttl: int) -> None:
        raise NotImplementedError

    async def delete(self, zone: str, name: str, record_type: str) -> None:
        raise NotImplementedError


class PowerDNSProvider(DNSProvider):
    def __init__(self, api_url: str, api_key: str) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key

    async def upsert(self, zone: str, name: str, record_type: str, value: str, ttl: int) -> None:
        name, value = _sanitise(name, value)
        payload = {
            "rrsets": [{
                "name": name, "type": record_type, "ttl": ttl,
                "changetype": "REPLACE",
                "records": [{"content": value, "disabled": False}],
            }]
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.patch(
                f"{self.api_url}/api/v1/servers/localhost/zones/{zone}",
                json=payload, headers={"X-API-Key": self.api_key},
            )
            resp.raise_for_status()

    async def delete(self, zone: str, name: str, record_type: str) -> None:
        name, _ = _sanitise(name, "placeholder")
        payload = {
            "rrsets": [{"name": name, "type": record_type, "changetype": "DELETE", "records": []}]
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.patch(
                f"{self.api_url}/api/v1/servers/localhost/zones/{zone}",
                json=payload, headers={"X-API-Key": self.api_key},
            )
            resp.raise_for_status()


class RFC2136Provider(DNSProvider):
    def __init__(self, server: str, key_name: str, key_secret: str) -> None:
        self.server = server
        self.key_name = key_name
        self.keyring = dns.tsigkeyring.from_text({key_name: key_secret}) if key_name else None

    def _update(self, zone: str) -> dns.update.Update:
        return dns.update.Update(
            zone,
            keyring=self.keyring,
            keyname=dns.name.from_text(self.key_name) if self.key_name else None,
        )

    async def upsert(self, zone: str, name: str, record_type: str, value: str, ttl: int) -> None:
        name, value = _sanitise(name, value)
        update = self._update(zone)
        update.replace(name, ttl, record_type, value)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, dns.query.tcp, update, self.server)

    async def delete(self, zone: str, name: str, record_type: str) -> None:
        name, _ = _sanitise(name, "placeholder")
        update = self._update(zone)
        update.delete(name, record_type)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, dns.query.tcp, update, self.server)


class Route53Provider(DNSProvider):
    """AWS Route 53 DNS provider using boto3."""

    def __init__(self, zone_id: str) -> None:
        self.zone_id = zone_id

    def _client(self):
        import boto3  # type: ignore
        return boto3.client("route53")

    async def upsert(self, zone: str, name: str, record_type: str, value: str, ttl: int) -> None:
        name, value = _sanitise(name, value)
        client = self._client()
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: client.change_resource_record_sets(
                HostedZoneId=self.zone_id,
                ChangeBatch={
                    "Changes": [{
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": name, "Type": record_type, "TTL": ttl,
                            "ResourceRecords": [{"Value": value}],
                        },
                    }]
                },
            ),
        )

    async def delete(self, zone: str, name: str, record_type: str) -> None:
        name, _ = _sanitise(name, "placeholder")
        client = self._client()
        loop = asyncio.get_event_loop()
        # Fetch current value first
        resp = await loop.run_in_executor(
            None,
            lambda: client.list_resource_record_sets(
                HostedZoneId=self.zone_id,
                StartRecordName=name, StartRecordType=record_type, MaxItems="1",
            ),
        )
        rrsets = resp.get("ResourceRecordSets", [])
        if not rrsets:
            return
        rrset = rrsets[0]
        await loop.run_in_executor(
            None,
            lambda: client.change_resource_record_sets(
                HostedZoneId=self.zone_id,
                ChangeBatch={"Changes": [{"Action": "DELETE", "ResourceRecordSet": rrset}]},
            ),
        )


class CloudflareProvider(DNSProvider):
    """Cloudflare DNS provider via REST API."""

    _BASE = "https://api.cloudflare.com/client/v4"

    def __init__(self, zone_id: str, api_token: str) -> None:
        self.zone_id = zone_id
        self.api_token = api_token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"}

    async def _find_record(self, name: str, record_type: str) -> str | None:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self._BASE}/zones/{self.zone_id}/dns_records",
                headers=self._headers(),
                params={"name": name, "type": record_type},
            )
            resp.raise_for_status()
            records = resp.json().get("result", [])
            return records[0]["id"] if records else None

    async def upsert(self, zone: str, name: str, record_type: str, value: str, ttl: int) -> None:
        name, value = _sanitise(name, value)
        record_id = await self._find_record(name, record_type)
        payload = {"type": record_type, "name": name, "content": value, "ttl": ttl}
        async with httpx.AsyncClient(timeout=10) as client:
            if record_id:
                resp = await client.put(
                    f"{self._BASE}/zones/{self.zone_id}/dns_records/{record_id}",
                    headers=self._headers(), json=payload,
                )
            else:
                resp = await client.post(
                    f"{self._BASE}/zones/{self.zone_id}/dns_records",
                    headers=self._headers(), json=payload,
                )
            resp.raise_for_status()

    async def delete(self, zone: str, name: str, record_type: str) -> None:
        name, _ = _sanitise(name, "placeholder")
        record_id = await self._find_record(name, record_type)
        if not record_id:
            return
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.delete(
                f"{self._BASE}/zones/{self.zone_id}/dns_records/{record_id}",
                headers=self._headers(),
            )
            resp.raise_for_status()
