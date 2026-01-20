from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator, Optional

import redis.asyncio as redis

from .models import Event

logger = logging.getLogger("adg.bus")

# Consumer group name used for Redis Streams — ensures offset is persisted
_CONSUMER_GROUP = "adg-controller"
_CONSUMER_NAME = "controller-0"


class EventBus:
    async def publish(self, event: Event) -> None:
        raise NotImplementedError

    def subscribe(self) -> AsyncIterator[Event]:
        raise NotImplementedError

    async def close(self) -> None:
        pass


class InMemoryBus(EventBus):
    """
    In-memory queue bus.  Backpressure: when full, the oldest item is dropped
    and a warning is emitted (rather than silently discarding the new one).
    """

    def __init__(self, max_size: int) -> None:
        self.queue: asyncio.Queue[Optional[Event]] = asyncio.Queue(maxsize=max_size)
        self._shutdown = asyncio.Event()

    async def publish(self, event: Event) -> None:
        if self.queue.full():
            try:
                dropped = self.queue.get_nowait()
                logger.warning("Bus full — dropped oldest event: %s", dropped)
            except asyncio.QueueEmpty:
                pass
        await self.queue.put(event)

    def subscribe(self) -> AsyncIterator[Event]:
        async def _generator() -> AsyncIterator[Event]:
            while not self._shutdown.is_set():
                try:
                    event = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                    if event is None:
                        break
                    yield event
                    self.queue.task_done()
                except asyncio.TimeoutError:
                    continue

        return _generator()

    async def close(self) -> None:
        """Signal consumer to drain then stop."""
        self._shutdown.set()
        # Drain remaining items so task_done() accounting is correct
        await self.queue.join()


class RedisStreamBus(EventBus):
    """
    Redis Streams bus with consumer group for durable offset tracking.
    Events are ACK'd after successful processing so no message is lost on restart.
    """

    def __init__(self, redis_url: str, stream: str = "adg-events") -> None:
        self._redis_url = redis_url
        self.stream = stream
        self.redis: Optional[redis.Redis] = None
        self._shutdown = asyncio.Event()

    async def _connect(self) -> None:
        if self.redis is None:
            self.redis = redis.from_url(self._redis_url, decode_responses=True)
            try:
                await self.redis.xgroup_create(self.stream, _CONSUMER_GROUP, id="0", mkstream=True)
            except Exception:
                pass  # Group already exists

    async def publish(self, event: Event) -> None:
        await self._connect()
        assert self.redis is not None
        await self.redis.xadd(self.stream, {"payload": event.model_dump_json()}, maxlen=10_000)

    def subscribe(self) -> AsyncIterator[Event]:
        async def _generator() -> AsyncIterator[Event]:
            await self._connect()
            assert self.redis is not None

            # First deliver any pending (unacked) messages from a previous crash
            pending = await self.redis.xreadgroup(
                _CONSUMER_GROUP, _CONSUMER_NAME,
                {self.stream: "0"}, count=100
            )
            for _, messages in pending:
                for msg_id, data in messages:
                    try:
                        yield Event.model_validate_json(data["payload"])
                        await self.redis.xack(self.stream, _CONSUMER_GROUP, msg_id)
                    except Exception as exc:
                        logger.error("Failed to process pending message %s: %s", msg_id, exc)

            # Normal loop — read new messages
            while not self._shutdown.is_set():
                try:
                    items = await self.redis.xreadgroup(
                        _CONSUMER_GROUP, _CONSUMER_NAME,
                        {self.stream: ">"}, block=1000, count=10
                    )
                except Exception as exc:
                    logger.warning("Redis read error, retrying: %s", exc)
                    await asyncio.sleep(2)
                    continue

                for _, messages in items:
                    for msg_id, data in messages:
                        try:
                            yield Event.model_validate_json(data["payload"])
                            await self.redis.xack(self.stream, _CONSUMER_GROUP, msg_id)
                        except Exception as exc:
                            logger.error("Failed to process message %s: %s", msg_id, exc)

        return _generator()

    async def close(self) -> None:
        self._shutdown.set()
        if self.redis:
            await self.redis.aclose()
