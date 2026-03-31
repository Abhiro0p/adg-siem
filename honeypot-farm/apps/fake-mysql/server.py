"""
Fake MySQL honeypot — listens on TCP 3306 and emulates the MySQL handshake.
Any connection attempt is logged as a structured event and forwarded to ADG.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
from datetime import datetime, timezone

import httpx

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("fake-mysql")

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "3306"))
WEBHOOK_URL = os.getenv("ADG_WEBHOOK_URL", "")
MYSQL_VERSION = "8.0.35"

# MySQL server greeting capability flags (simulated)
_CAP_FLAGS = 0x0001FFFF
_CHARSET = 33  # utf8
_AUTH_PLUGIN = b"caching_sha2_password\x00"
_SCRAMBLE = b"adgfaketoken123456789012"  # 20-byte scramble + null


def _build_handshake_packet() -> bytes:
    """Build MySQL Protocol v10 handshake packet."""
    payload = (
        b"\x0a"  # protocol version 10
        + MYSQL_VERSION.encode() + b"\x00"
        + struct.pack("<I", 1)  # connection_id = 1
        + _SCRAMBLE[:8] + b"\x00"  # auth-plugin-data-part-1
        + struct.pack("<H", _CAP_FLAGS & 0xFFFF)  # capability flags lower
        + bytes([_CHARSET])  # character set
        + struct.pack("<H", 2)  # status flags
        + struct.pack("<H", (_CAP_FLAGS >> 16) & 0xFFFF)  # capability flags upper
        + bytes([len(_AUTH_PLUGIN)])  # length of auth-plugin-data
        + b"\x00" * 10  # reserved
        + _SCRAMBLE[8:] + b"\x00"  # auth-plugin-data-part-2
        + _AUTH_PLUGIN
    )
    length = struct.pack("<I", len(payload))[:3]
    return length + b"\x00" + payload  # seq=0


def _parse_client_handshake(data: bytes) -> dict:
    """Extract username and db from MySQL client handshake packet."""
    if len(data) < 36:
        return {}
    try:
        # Skip packet header (4 bytes) + capability flags (4) + max_packet_size (4) + charset (1) + reserved (23)
        offset = 4 + 4 + 4 + 1 + 23
        username_end = data.index(b"\x00", offset)
        username = data[offset:username_end].decode("utf-8", errors="replace")
        return {"username": username}
    except (ValueError, IndexError):
        return {}


async def _forward_event(src_ip: str, src_port: int, client_info: dict) -> None:
    event = {
        "source": "fake-mysql",
        "event_type": "auth_attempt",
        "ts": datetime.now(timezone.utc).isoformat(),
        "data": {
            "src_ip": src_ip,
            "src_port": src_port,
            "port": LISTEN_PORT,
            "protocol": "mysql",
            "service": "mysql",
            "username": client_info.get("username", ""),
            "mysql_version": MYSQL_VERSION,
        },
    }
    logger.info(json.dumps(event))
    if WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                await client.post(WEBHOOK_URL, json=event)
        except Exception:
            pass


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername", ("unknown", 0))
    src_ip, src_port = peer[0], peer[1]
    try:
        writer.write(_build_handshake_packet())
        await writer.drain()

        # Read client response (handshake response packet)
        data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        client_info = _parse_client_handshake(data)
        await _forward_event(src_ip, src_port, client_info)

        # Send authentication error
        err_msg = b"Access denied for user"
        error_pkt = (
            struct.pack("<I", len(err_msg) + 9)[:3] + b"\x02"  # seq=2
            + b"\xff"  # ERR marker
            + struct.pack("<H", 1045)  # error code ER_ACCESS_DENIED_ERROR
            + b"#28000"  # SQL state
            + err_msg
        )
        writer.write(error_pkt)
        await writer.drain()
    except asyncio.TimeoutError:
        pass
    except Exception as exc:
        logger.debug("Connection error from %s: %s", src_ip, exc)
    finally:
        writer.close()


async def main() -> None:
    server = await asyncio.start_server(handle_connection, LISTEN_HOST, LISTEN_PORT)
    logger.info("Fake MySQL listening on %s:%d", LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
