from __future__ import annotations

import asyncio
from typing import Callable

import redis.asyncio as redis


class LeaderElector:
    def __init__(self, redis_url: str, lock_key: str, ttl: int) -> None:
        self.redis = redis.from_url(redis_url)
        self.lock_key = lock_key
        self.ttl = ttl

    async def run(self, on_change: Callable[[bool], None]) -> None:
        is_leader = False
        while True:
            acquired = await self.redis.set(self.lock_key, "1", ex=self.ttl, nx=True)
            if acquired:
                if not is_leader:
                    is_leader = True
                    on_change(True)
            else:
                current = await self.redis.ttl(self.lock_key)
                if current < 0:
                    await self.redis.set(self.lock_key, "1", ex=self.ttl, nx=True)
                if is_leader:
                    is_leader = False
                    on_change(False)
            await asyncio.sleep(max(1, self.ttl // 2))
