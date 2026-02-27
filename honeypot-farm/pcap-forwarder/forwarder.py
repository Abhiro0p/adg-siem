"""
PCAP Forwarder — watches a directory for new PCAP files and publishes them
to Kafka with SHA-256 integrity hashes and exponential retry backoff.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Set

from kafka import KafkaProducer
from kafka.errors import KafkaError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("pcap-forwarder")

PCAP_DIR = Path(os.getenv("PCAP_DIR", "/pcap"))
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "pcap-events")
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "5"))
MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "50"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "5"))

_MAX_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
_SEEN_FILE = PCAP_DIR / ".forwarded"


def _load_seen() -> Set[str]:
    if _SEEN_FILE.exists():
        return set(_SEEN_FILE.read_text().splitlines())
    return set()


def _save_seen(seen: Set[str]) -> None:
    _SEEN_FILE.write_text("\n".join(sorted(seen)))


def _build_producer() -> KafkaProducer:
    backoff = 2
    for attempt in range(10):
        try:
            producer = KafkaProducer(
                bootstrap_servers=KAFKA_BROKER,
                acks="all",
                retries=5,
                max_block_ms=10_000,
            )
            logger.info("Connected to Kafka at %s", KAFKA_BROKER)
            return producer
        except KafkaError as exc:
            logger.warning("Kafka connect attempt %d failed: %s — retrying in %ds", attempt + 1, exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
    raise RuntimeError(f"Could not connect to Kafka at {KAFKA_BROKER} after 10 attempts")


def _send_with_retry(producer: KafkaProducer, payload: bytes, retries: int = MAX_RETRIES) -> bool:
    backoff = 1
    for attempt in range(retries):
        try:
            future = producer.send(KAFKA_TOPIC, value=payload)
            producer.flush(timeout=30)
            future.get(timeout=30)
            return True
        except KafkaError as exc:
            if attempt == retries - 1:
                logger.error("Failed to send after %d retries: %s", retries, exc)
                return False
            logger.warning("Send attempt %d failed: %s — retrying in %ds", attempt + 1, exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
    return False


def _process_file(path: Path, producer: KafkaProducer) -> bool:
    size = path.stat().st_size
    if size > _MAX_BYTES:
        logger.warning("Skipping %s — size %dMB exceeds limit %dMB", path.name, size // (1024**2), MAX_FILE_SIZE_MB)
        return True  # Mark as seen to avoid re-checking

    with path.open("rb") as fh:
        raw = fh.read()

    sha256 = hashlib.sha256(raw).hexdigest()
    encoded = base64.b64encode(raw).decode("utf-8")

    envelope = json.dumps({
        "filename": path.name,
        "sha256": sha256,
        "size_bytes": size,
        "ts": time.time(),
        "data": encoded,
    }).encode("utf-8")

    ok = _send_with_retry(producer, envelope)
    if ok:
        logger.info("Forwarded %s (%d bytes, sha256=%s)", path.name, size, sha256)
    return ok


def main() -> None:
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    seen = _load_seen()
    producer = _build_producer()

    logger.info("Watching %s for PCAP files (poll every %ds)", PCAP_DIR, POLL_INTERVAL)

    while True:
        try:
            for entry in sorted(PCAP_DIR.iterdir()):
                if not entry.name.endswith(".pcap"):
                    continue
                key = str(entry)
                if key in seen:
                    continue
                if _process_file(entry, producer):
                    seen.add(key)
                    _save_seen(seen)
        except OSError as exc:
            logger.error("Directory scan error: %s", exc)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
