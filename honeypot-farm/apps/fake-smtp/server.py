"""
Fake SMTP honeypot — emulates a mail server on port 25/587.
Logs all AUTH and EHLO attempts as structured events.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
from datetime import datetime, timezone

import httpx

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("fake-smtp")

LISTEN_HOST = os.getenv("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "25"))
WEBHOOK_URL = os.getenv("ADG_WEBHOOK_URL", "")
HOSTNAME = os.getenv("SMTP_HOSTNAME", "mail.corp-internal.local")

_SAFE_RE = re.compile(r"[^\x20-\x7E]")


def _sanitize(s: str, maxlen: int = 512) -> str:
    return _SAFE_RE.sub("", s)[:maxlen]


async def _forward_event(src_ip: str, event_type: str, details: dict) -> None:
    event = {
        "source": "fake-smtp",
        "event_type": event_type,
        "ts": datetime.now(timezone.utc).isoformat(),
        "data": {"src_ip": src_ip, "port": LISTEN_PORT, "protocol": "smtp", "service": "smtp", **details},
    }
    logger.info(json.dumps(event))
    if WEBHOOK_URL:
        try:
            async with httpx.AsyncClient(timeout=3) as c:
                await c.post(WEBHOOK_URL, json=event)
        except Exception:
            pass


async def handle_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername", ("unknown", 0))
    src_ip = peer[0]

    async def send(line: str) -> None:
        writer.write((line + "\r\n").encode())
        await writer.drain()

    try:
        await send(f"220 {HOSTNAME} ESMTP Postfix (Debian/GNU)")

        while True:
            raw = await asyncio.wait_for(reader.readline(), timeout=30.0)
            if not raw:
                break
            line = _sanitize(raw.decode("utf-8", errors="replace").strip())
            cmd = line.upper().split(" ", 1)[0]

            if cmd == "EHLO" or cmd == "HELO":
                domain = line[5:].strip() if len(line) > 5 else ""
                await _forward_event(src_ip, "smtp_ehlo", {"ehlo_domain": domain})
                await send(f"250-{HOSTNAME}")
                await send("250-AUTH LOGIN PLAIN")
                await send("250-SIZE 52428800")
                await send("250 STARTTLS")

            elif cmd == "AUTH":
                args = line[5:].strip()
                mech = args.split(" ", 1)[0].upper()
                credentials = args[len(mech):].strip()
                try:
                    decoded = base64.b64decode(credentials).decode("utf-8", errors="replace")
                except Exception:
                    decoded = credentials
                await _forward_event(src_ip, "auth_attempt", {
                    "mechanism": mech, "credential_raw": _sanitize(decoded, 256)
                })
                await send("535 5.7.8 Authentication credentials invalid")

            elif cmd == "MAIL":
                await send("250 Ok")
            elif cmd == "RCPT":
                await send("250 Ok")
            elif cmd == "DATA":
                await send("354 End data with <CR><LF>.<CR><LF>")
            elif cmd == "QUIT":
                await send("221 Bye")
                break
            elif cmd == "STARTTLS":
                await send("454 TLS not available due to local problem")
            else:
                await send("500 Command not recognized")

    except asyncio.TimeoutError:
        pass
    except Exception as exc:
        logger.debug("SMTP error from %s: %s", src_ip, exc)
    finally:
        writer.close()


async def main() -> None:
    server = await asyncio.start_server(handle_connection, LISTEN_HOST, LISTEN_PORT)
    logger.info("Fake SMTP listening on %s:%d", LISTEN_HOST, LISTEN_PORT)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
