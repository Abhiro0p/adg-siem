from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("adg.audit")

# ---------------------------------------------------------------------------
# HTTP request audit middleware
# ---------------------------------------------------------------------------

class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, log_path: str) -> None:
        super().__init__(app)
        self.log_path = log_path
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        start = time.time()

        response: Response = await call_next(request)

        entry: Dict[str, Any] = {
            "ts": time.time(),
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query) if request.url.query else None,
            "status": response.status_code,
            "latency_ms": int((time.time() - start) * 1000),
            "client_ip": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
            "subject": getattr(getattr(request.state, "principal", None), "subject", None),
        }

        self._write(entry)
        response.headers["X-Request-ID"] = request_id
        return response

    def _write(self, entry: Dict[str, Any]) -> None:
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to write audit log: %s", exc)


# ---------------------------------------------------------------------------
# Action-level audit logger (used by business logic, not just HTTP)
# ---------------------------------------------------------------------------

class ActionAuditLogger:
    def __init__(self, log_path: str) -> None:
        self.log_path = log_path
        Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        action: str,
        subject: str,
        resource: str,
        outcome: str,
        details: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> None:
        entry: Dict[str, Any] = {
            "ts": time.time(),
            "request_id": request_id or str(uuid.uuid4()),
            "action": action,
            "subject": subject,
            "resource": resource,
            "outcome": outcome,
            "details": details or {},
        }
        try:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, default=str) + "\n")
        except OSError as exc:
            logger.error("Failed to write action audit: %s", exc)

    def log_rule_fired(
        self,
        rule_name: str,
        event_source: str,
        actions: list,
        request_id: Optional[str] = None,
    ) -> None:
        self.log(
            action="rule_fired",
            subject="rule_engine",
            resource=rule_name,
            outcome="matched",
            details={"event_source": event_source, "triggered_actions": actions},
            request_id=request_id,
        )

    def log_honeypot_decision(
        self,
        rule_name: str,
        subnet: str,
        allowed: bool,
        reason: str,
        request_id: Optional[str] = None,
    ) -> None:
        self.log(
            action="honeypot_deploy_decision",
            subject="policy_engine",
            resource=subnet,
            outcome="allowed" if allowed else "blocked",
            details={"rule": rule_name, "reason": reason},
            request_id=request_id,
        )
