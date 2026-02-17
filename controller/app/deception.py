from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Deque, Dict, List, Tuple

from .models import Event

# ---------------------------------------------------------------------------
# Realism scoring — multi-factor, weighted
# ---------------------------------------------------------------------------

_HIGH_VALUE_PORTS = {21, 22, 23, 25, 53, 80, 110, 143, 389, 443, 445, 1433, 1521,
                     3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}

_SUSPICIOUS_UA_PATTERNS = {
    "masscan", "nmap", "zmap", "zgrab", "shodan", "censys", "python-requests",
    "go-http-client", "curl", "wget", "httpx", "nuclei", "metasploit", "sqlmap",
}


def realism_score(event: Event) -> Dict[str, Any]:
    """
    Return a scored assessment of an event's deception value.
    Score components:
      - network_signals (0.0-0.35): interesting port, subnet, protocol
      - credential_signals (0.0-0.25): auth attempts, credential quality
      - behaviour_signals (0.0-0.25): user agent, tool fingerprint, timing
      - context_signals (0.0-0.15): event type match, enrichment presence
    """
    # Merge explicit data dict with any extra top-level fields (flat honeypot payloads)
    data = {**event.model_extra, **event.data} if event.model_extra else event.data
    breakdown: Dict[str, float] = {}

    # Network signals
    net = 0.0
    port = data.get("port")
    if isinstance(port, int) and port in _HIGH_VALUE_PORTS:
        net += 0.20
    elif port is not None:
        net += 0.05
    if data.get("src_ip"):
        net += 0.10
    if data.get("protocol") in {"smb", "rdp", "ssh", "ftp", "ldap", "http", "https"}:
        net += 0.05
    breakdown["network"] = min(net, 0.35)

    # Credential signals
    cred = 0.0
    if data.get("credential") or data.get("username"):
        cred += 0.15
    if data.get("password"):
        cred += 0.10
    breakdown["credential"] = min(cred, 0.25)

    # Behaviour signals
    beh = 0.0
    ua = str(data.get("user_agent", "")).lower()
    if ua:
        beh += 0.10
        for pattern in _SUSPICIOUS_UA_PATTERNS:
            if pattern in ua:
                beh += 0.10
                break
    if data.get("command") or data.get("payload"):
        beh += 0.05
    breakdown["behaviour"] = min(beh, 0.25)

    # Context signals
    ctx = 0.0
    if event.event_type in {"auth_attempt", "brute_force", "scan", "c2_beacon", "exploit"}:
        ctx += 0.10
    if data.get("enrichment") or data.get("geo_country"):
        ctx += 0.05
    breakdown["context"] = min(ctx, 0.15)

    total = sum(breakdown.values())
    confidence = _sigmoid(total * 8 - 4)  # map 0-1 to a confidence curve

    return {
        "score": round(total, 3),
        "confidence": round(confidence, 3),
        "breakdown": {k: round(v, 3) for k, v in breakdown.items()},
        "label": _label(total),
    }


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _label(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Coverage map
# ---------------------------------------------------------------------------

def coverage_map(events: List[Event]) -> Dict[str, Any]:
    """Return coverage statistics grouped by subnet and event type."""
    by_subnet: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    by_source: Dict[str, int] = {}

    for event in events:
        flat = {**event.model_extra, **event.data} if event.model_extra else event.data
        src_ip = flat.get("src_ip", "")
        subnet = flat.get("subnet") or (src_ip.rsplit(".", 1)[0] + ".0/24" if src_ip else "unknown")
        by_subnet[subnet] = by_subnet.get(subnet, 0) + 1
        by_type[event.event_type] = by_type.get(event.event_type, 0) + 1
        by_source[event.source] = by_source.get(event.source, 0) + 1

    return {
        "by_subnet": by_subnet,
        "by_event_type": by_type,
        "by_source": by_source,
        "total": len(events),
    }


# ---------------------------------------------------------------------------
# Behavioural baseline — rolling per-source event rate anomaly detection
# ---------------------------------------------------------------------------

class BaselineTracker:
    """
    Tracks per-source event rates and flags sources that deviate significantly
    from their recent baseline (simple z-score on sliding window).
    """

    def __init__(self, window_seconds: int = 300, z_threshold: float = 3.0) -> None:
        self.window = window_seconds
        self.z_threshold = z_threshold
        self._events: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def record(self, source: str) -> Dict[str, Any]:
        now = time.time()
        with self._lock:
            dq = self._events[source]
            dq.append(now)
            cutoff = now - self.window
            while dq and dq[0] < cutoff:
                dq.popleft()
            count = len(dq)

        rate = count / max(self.window / 60.0, 1)  # events per minute
        is_anomaly = count > 2 and self._is_anomaly(source, count)
        return {"source": source, "event_count": count, "rate_per_min": round(rate, 2), "anomaly": is_anomaly}

    def _is_anomaly(self, source: str, current: int) -> bool:
        dq = self._events[source]
        if len(dq) < 5:
            return False
        values = list(dq)
        # Bucket into 10s intervals
        buckets: Dict[int, int] = defaultdict(int)
        for ts in values:
            bucket = int(ts / 10)
            buckets[bucket] += 1
        counts = list(buckets.values())
        if len(counts) < 3:
            return False
        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        std = math.sqrt(variance) if variance > 0 else 1.0
        z = (current - mean) / std
        return z > self.z_threshold


_baseline_tracker = BaselineTracker()
