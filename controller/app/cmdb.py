from __future__ import annotations

from typing import Dict, List

import httpx


def fetch_assets(cmdb_url: str, token: str, subnet: str | None = None) -> List[Dict]:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    params = {"subnet": subnet} if subnet else {}
    response = httpx.get(cmdb_url, headers=headers, params=params, timeout=10)
    response.raise_for_status()
    return response.json()
