from __future__ import annotations

import httpx

from .models import TokenAccess


class WebhookEmitter:
    def __init__(self, url: str) -> None:
        self.url = url

    async def emit(self, access: TokenAccess) -> None:
        if not self.url:
            return
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(self.url, json=access.model_dump())
        except Exception:
            pass
