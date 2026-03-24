import asyncio
import httpx


async def fire_event(session):
    payload = {
        "source": "zeek",
        "event_type": "port_scan",
        "data": {"port": 8080, "src_ip": "10.10.20.50"},
    }
    await session.post("http://localhost:8080/events", json=payload, timeout=5)


async def main():
    async with httpx.AsyncClient() as session:
        tasks = [fire_event(session) for _ in range(100)]
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
