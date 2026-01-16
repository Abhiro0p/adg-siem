from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from .orchestrator import Orchestrator
from .state import StateStore


class TTLReaper:
    def __init__(self, store: StateStore, orchestrator: Orchestrator, interval: int) -> None:
        self.store = store
        self.orchestrator = orchestrator
        self.interval = interval

    async def run(self) -> None:
        while True:
            now = datetime.now(timezone.utc)
            for lure in list(self.store.expired_lures(now)):
                await self.orchestrator.teardown(lure)
            await asyncio.sleep(self.interval)
