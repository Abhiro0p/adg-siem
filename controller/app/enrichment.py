"""
Event enrichment: GeoIP, ASN, reverse DNS, AbuseIPDB, OTX lookups.
All lookups are best-effort — failures are logged but never raise.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from typing import Any, Dict

import httpx

logger = logging.getLogger("adg.enrichment")

# ---------------------------------------------------------------------------
# GeoIP via ip-api.com (free, no key required, 45 req/min from same IP)
# For production replace with MaxMind GeoIP2 or IPinfo.
# ---------------------------------------------------------------------------
_GEOIP_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting"
_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_OTX_INDICATORS_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"


async def enrich_ip(
    ip: str,
    abuseipdb_key: str = "",
    otx_key: str = "",
) -> Dict[str, Any]:
    """Return enrichment dict for an IP address."""
    if not _is_routable(ip):
        return {"ip": ip, "routable": False}

    results: Dict[str, Any] = {"ip": ip, "routable": True}
    tasks = [
        _geoip(ip),
        _reverse_dns(ip),
    ]
    if abuseipdb_key:
        tasks.append(_abuseipdb(ip, abuseipdb_key))
    if otx_key:
        tasks.append(_otx(ip, otx_key))

    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    for item in gathered:
        if isinstance(item, dict):
            results.update(item)
        elif isinstance(item, Exception):
            logger.debug("Enrichment lookup failed: %s", item)

    return results


def _is_routable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False


async def _geoip(ip: str) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(_GEOIP_URL.format(ip=ip))
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") != "success":
            return {}
        return {
            "geo_country": data.get("country"),
            "geo_country_code": data.get("countryCode"),
            "geo_region": data.get("regionName"),
            "geo_city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "asn_name": data.get("asname"),
            "is_mobile": data.get("mobile", False),
            "is_proxy": data.get("proxy", False),
            "is_hosting": data.get("hosting", False),
        }


async def _reverse_dns(ip: str) -> Dict[str, Any]:
    loop = asyncio.get_event_loop()
    try:
        hostname = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return {"rdns": hostname[0]}
    except Exception:
        return {"rdns": None}


async def _abuseipdb(ip: str, api_key: str) -> Dict[str, Any]:
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": ""}
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(_ABUSEIPDB_URL, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json().get("data", {})
        return {
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "abuse_total_reports": data.get("totalReports", 0),
            "abuse_last_reported": data.get("lastReportedAt"),
            "abuse_is_whitelisted": data.get("isWhitelisted", False),
        }


async def _otx(ip: str, api_key: str) -> Dict[str, Any]:
    headers = {"X-OTX-API-KEY": api_key}
    async with httpx.AsyncClient(timeout=5) as client:
        resp = await client.get(_OTX_INDICATORS_URL.format(ip=ip), headers=headers)
        resp.raise_for_status()
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return {
            "otx_pulse_count": pulse_count,
            "otx_threat_score": min(pulse_count * 10, 100),
        }
