from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("adg.soar.sentinelone")


def isolate_device(api_url: str, token: str, device_id: str) -> None:
    """
    Network-isolate an agent by IP or device ID via SentinelOne Management API.
    The 'device_id' parameter can be a SentinelOne agent UUID or a queried IP.
    """
    headers = {"Authorization": f"ApiToken {token}", "Content-Type": "application/json"}
    base = api_url.rstrip("/")

    # Resolve IP to agent ID if needed
    agent_id = device_id
    if "." in device_id or ":" in device_id:
        resp = httpx.get(
            f"{base}/web/api/v2.1/agents",
            headers=headers,
            params={"networkInterfaceInet__contains": device_id},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json().get("data", [])
        if not data:
            logger.warning("SentinelOne: no agent found for IP %s", device_id)
            return
        agent_id = data[0]["id"]

    resp = httpx.post(
        f"{base}/web/api/v2.1/agents/actions/disconnect",
        headers=headers,
        json={"filter": {"ids": [agent_id]}},
        timeout=10,
    )
    resp.raise_for_status()
    logger.info("SentinelOne: isolated agent %s", agent_id)
