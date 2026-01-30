from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import time
from base64 import b64encode
from typing import Dict, List, Optional

import httpx

from .models import AlertPayload

logger = logging.getLogger("adg.siem")

_MAX_RETRIES = 3
_RETRY_BACKOFF = [1, 3, 7]  # seconds


async def _post_with_retry(
    url: str,
    payload: dict,
    headers: dict,
    timeout: int = 10,
) -> None:
    for attempt, backoff in enumerate(_RETRY_BACKOFF):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                return
        except (httpx.HTTPError, httpx.TimeoutException) as exc:
            if attempt == _MAX_RETRIES - 1:
                logger.error("SIEM emit failed after %d retries: %s", _MAX_RETRIES, exc)
                raise
            logger.warning("SIEM emit attempt %d failed, retrying in %ds: %s", attempt + 1, backoff, exc)
            await asyncio.sleep(backoff)


class SIEMEmitter:
    async def emit(self, alert: AlertPayload) -> None:
        raise NotImplementedError

    async def health(self) -> Dict[str, bool]:
        return {"ok": True}


class WebhookEmitter(SIEMEmitter):
    def __init__(self, url: str, secret: str = "") -> None:
        self.url = url
        self.secret = secret

    async def emit(self, alert: AlertPayload) -> None:
        payload = alert.model_dump()
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.secret:
            body = json.dumps(payload, default=str).encode()
            sig = hmac.new(self.secret.encode(), body, hashlib.sha256).hexdigest()
            headers["X-ADG-Signature"] = f"sha256={sig}"
        await _post_with_retry(self.url, payload, headers)

    async def health(self) -> Dict[str, bool]:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                resp = await client.get(self.url.rsplit("/", 1)[0] + "/health")
                return {"ok": resp.status_code < 500}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


class SplunkHECEmitter(SIEMEmitter):
    def __init__(self, url: str, token: str, index: str = "main") -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.index = index

    async def emit(self, alert: AlertPayload) -> None:
        payload = {
            "time": time.time(),
            "event": alert.model_dump(),
            "index": self.index,
            "sourcetype": "adg:alert",
            "source": alert.event.source,
        }
        headers = {"Authorization": f"Splunk {self.token}"}
        await _post_with_retry(f"{self.url}/services/collector", payload, headers)

    async def health(self) -> Dict[str, bool]:
        try:
            headers = {"Authorization": f"Splunk {self.token}"}
            async with httpx.AsyncClient(timeout=3) as client:
                resp = await client.get(f"{self.url}/services/collector/health", headers=headers)
                return {"ok": resp.status_code == 200}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


class ElasticEmitter(SIEMEmitter):
    def __init__(self, url: str, api_key: str, index: str = "adg-alerts") -> None:
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.index = index

    async def emit(self, alert: AlertPayload) -> None:
        headers = {"Authorization": f"ApiKey {self.api_key}"}
        await _post_with_retry(f"{self.url}/{self.index}/_doc", alert.model_dump(), headers)

    async def health(self) -> Dict[str, bool]:
        try:
            headers = {"Authorization": f"ApiKey {self.api_key}"}
            async with httpx.AsyncClient(timeout=3) as client:
                resp = await client.get(f"{self.url}/_cluster/health", headers=headers)
                return {"ok": resp.status_code == 200}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}


class SentinelEmitter(SIEMEmitter):
    """Microsoft Azure Sentinel / Log Analytics Workspace emitter."""

    def __init__(self, workspace_id: str, shared_key: str, log_type: str = "ADGAlert") -> None:
        self.workspace_id = workspace_id
        self.shared_key = shared_key
        self.log_type = log_type
        self.url = (
            f"https://{workspace_id}.ods.opinsights.azure.com"
            f"/api/logs?api-version=2016-04-01"
        )

    def _build_signature(self, date: str, content_length: int) -> str:
        string_to_hash = (
            f"POST\n{content_length}\napplication/json\n"
            f"x-ms-date:{date}\n/api/logs"
        )
        decoded_key = b64encode(self.shared_key.encode()).decode()
        import base64, hmac as _hmac, hashlib as _hs
        key_bytes = base64.b64decode(decoded_key)
        encoded = _hmac.new(key_bytes, string_to_hash.encode("utf-8"), _hs.sha256).digest()
        return b64encode(encoded).decode()

    async def emit(self, alert: AlertPayload) -> None:
        from email.utils import formatdate
        body = json.dumps([alert.model_dump()], default=str).encode("utf-8")
        rfc1123date = formatdate(usegmt=True)
        signature = self._build_signature(rfc1123date, len(body))
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"SharedKey {self.workspace_id}:{signature}",
            "Log-Type": self.log_type,
            "x-ms-date": rfc1123date,
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(self.url, content=body, headers=headers)
            resp.raise_for_status()


class SumoLogicEmitter(SIEMEmitter):
    def __init__(self, url: str) -> None:
        self.url = url

    async def emit(self, alert: AlertPayload) -> None:
        headers = {"Content-Type": "application/json", "X-Sumo-Category": "adg/alerts"}
        await _post_with_retry(self.url, alert.model_dump(), headers)


class DatadogEmitter(SIEMEmitter):
    def __init__(self, api_key: str, site: str = "datadoghq.com") -> None:
        self.url = f"https://http-intake.logs.{site}/api/v2/logs"
        self.api_key = api_key

    async def emit(self, alert: AlertPayload) -> None:
        payload = {
            "ddsource": "adg",
            "ddtags": f"rule:{alert.rule_name},severity:{alert.severity}",
            "hostname": alert.event.source,
            "service": "adg-controller",
            "message": json.dumps(alert.model_dump(), default=str),
        }
        headers = {"DD-API-KEY": self.api_key, "Content-Type": "application/json"}
        await _post_with_retry(self.url, payload, headers)


class MultiEmitter(SIEMEmitter):
    """Fan-out to multiple SIEM targets in parallel."""

    def __init__(self, emitters: List[SIEMEmitter]) -> None:
        self.emitters = emitters

    async def emit(self, alert: AlertPayload) -> None:
        results = await asyncio.gather(
            *[e.emit(alert) for e in self.emitters], return_exceptions=True
        )
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error("SIEM emitter[%d] failed: %s", i, result)

    async def health(self) -> Dict[str, bool]:
        results = await asyncio.gather(
            *[e.health() for e in self.emitters], return_exceptions=True
        )
        return {f"emitter_{i}": r if isinstance(r, dict) else {"ok": False} for i, r in enumerate(results)}


def build_siem_emitter(config: Dict[str, str]) -> SIEMEmitter:
    mode = config.get("mode", "webhook")
    modes = [m.strip() for m in mode.split(",")]

    def _build_one(m: str) -> SIEMEmitter:
        if m == "splunk":
            return SplunkHECEmitter(config["url"], config.get("token", ""), config.get("index", "main"))
        if m == "elastic":
            return ElasticEmitter(config["url"], config.get("token", ""), config.get("index", "adg-alerts"))
        if m == "sentinel":
            return SentinelEmitter(config.get("workspace_id", ""), config.get("shared_key", ""))
        if m == "sumologic":
            return SumoLogicEmitter(config["url"])
        if m == "datadog":
            return DatadogEmitter(config.get("token", ""), config.get("site", "datadoghq.com"))
        return WebhookEmitter(config.get("url", ""), config.get("webhook_secret", ""))

    if len(modes) == 1:
        return _build_one(modes[0])
    return MultiEmitter([_build_one(m) for m in modes])
