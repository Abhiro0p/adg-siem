"""
Deep health checks for /health/ready and /health/live endpoints.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict

import httpx
import redis.asyncio as aioredis

logger = logging.getLogger("adg.health")


async def check_postgres(db_url: str) -> Dict[str, Any]:
    if not db_url.startswith("postgres"):
        return {"ok": True, "skip": "non-postgres"}
    try:
        import psycopg
        conn = await psycopg.AsyncConnection.connect(db_url)
        await conn.execute("SELECT 1")
        await conn.close()
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def check_redis(redis_url: str) -> Dict[str, Any]:
    if not redis_url:
        return {"ok": True, "skip": "not configured"}
    try:
        r = aioredis.from_url(redis_url, socket_connect_timeout=2)
        await r.ping()
        await r.aclose()
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def check_vault(vault_addr: str, vault_token: str) -> Dict[str, Any]:
    if not vault_addr:
        return {"ok": True, "skip": "not configured"}
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(
                f"{vault_addr}/v1/sys/health",
                headers={"X-Vault-Token": vault_token},
            )
            return {"ok": resp.status_code in {200, 429, 473}, "status": resp.status_code}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def check_siem(siem_url: str) -> Dict[str, Any]:
    if not siem_url:
        return {"ok": True, "skip": "not configured"}
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            resp = await client.get(siem_url.rstrip("/") + "/health")
            return {"ok": resp.status_code < 500}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def run_readiness_checks(
    db_url: str,
    redis_url: str,
    vault_addr: str,
    vault_token: str,
    siem_url: str,
) -> Dict[str, Any]:
    start = time.time()
    results = await asyncio.gather(
        check_postgres(db_url),
        check_redis(redis_url),
        check_vault(vault_addr, vault_token),
        check_siem(siem_url),
        return_exceptions=True,
    )
    checks = {
        "database": results[0] if not isinstance(results[0], Exception) else {"ok": False, "error": str(results[0])},
        "redis": results[1] if not isinstance(results[1], Exception) else {"ok": False, "error": str(results[1])},
        "vault": results[2] if not isinstance(results[2], Exception) else {"ok": False, "error": str(results[2])},
        "siem": results[3] if not isinstance(results[3], Exception) else {"ok": False, "error": str(results[3])},
    }
    all_ok = all(c.get("ok", False) for c in checks.values())
    return {
        "ready": all_ok,
        "checks": checks,
        "latency_ms": int((time.time() - start) * 1000),
    }
