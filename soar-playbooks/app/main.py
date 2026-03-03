from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace import TracerProvider
from prometheus_fastapi_instrumentator import Instrumentator
from pythonjsonlogger import jsonlogger
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from .audit import AuditMiddleware
from .auth import principal_dependency, require_roles
from .config import Settings
from .models import Alert
from .playbook_engine import PlaybookEngine
from .responses import ResponseActions
from .secrets import load_vault_secrets
from .security import MTLSVerifier

logger = logging.getLogger("adg.soar")
_handler = logging.StreamHandler()
_handler.setFormatter(jsonlogger.JsonFormatter())
logger.addHandler(_handler)
logger.setLevel(logging.INFO)

settings = Settings()
vault_data = load_vault_secrets(settings)
for _key in ("jwt_secret", "defender_url", "defender_token", "crowdstrike_url",
             "crowdstrike_token", "sentinelone_url", "sentinelone_token",
             "ise_url", "ise_user", "ise_password",
             "slack_webhook_url", "pagerduty_routing_key",
             "jira_url", "jira_user", "jira_token",
             "ad_server", "ad_user", "ad_password", "ad_base_dn"):
    if _key in vault_data:
        setattr(settings, _key, vault_data[_key])

mtls_verifier = MTLSVerifier(settings.mtls_required)
principal_dep = principal_dependency(settings.jwt_secret, settings.jwt_algorithm)

app = FastAPI(
    title="ADG SOAR Playbooks",
    version="2.0.0",
    description="Automated Security Orchestration, Automation & Response for ADG.",
    dependencies=[Depends(mtls_verifier)],
)
app.add_middleware(AuditMiddleware, log_path=settings.audit_log_path)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store",
        })
        return response


app.add_middleware(_SecurityHeadersMiddleware)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

actions = ResponseActions(
    defender_url=settings.defender_url,
    defender_token=settings.defender_token,
    crowdstrike_url=settings.crowdstrike_url,
    crowdstrike_token=settings.crowdstrike_token,
    sentinelone_url=settings.sentinelone_url,
    sentinelone_token=settings.sentinelone_token,
    ise_url=settings.ise_url,
    ise_user=settings.ise_user,
    ise_password=settings.ise_password,
    slack_webhook_url=settings.slack_webhook_url,
    pagerduty_routing_key=settings.pagerduty_routing_key,
    jira_url=settings.jira_url,
    jira_user=settings.jira_user,
    jira_token=settings.jira_token,
    jira_project=settings.jira_project,
    ad_server=settings.ad_server,
    ad_user=settings.ad_user,
    ad_password=settings.ad_password,
    ad_base_dn=settings.ad_base_dn,
)
engine = PlaybookEngine.from_yaml("./playbooks/default.yaml", actions)

resource = Resource(attributes={"service.name": "soar-playbooks", "service.version": "2.0.0"})
provider = TracerProvider(resource=resource)
if settings.otlp_endpoint:
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otlp_endpoint)))
trace.set_tracer_provider(provider)
FastAPIInstrumentor.instrument_app(app)
Instrumentator().instrument(app).expose(app)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})


@app.get("/health/live", summary="Liveness probe")
async def health_live() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/health", include_in_schema=False)
async def health_legacy() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/alerts", summary="Receive an alert and run matching playbooks")
@limiter.limit(settings.rate_limit)
async def ingest_alert(
    request: Request,
    alert: Alert,
    principal=Depends(require_roles(principal_dep, ["soar:write"])),
) -> Dict[str, Any]:
    results = await engine.handle_alert(alert)
    logger.info({"alert": alert.model_dump(), "results": results})
    return {"status": "processed", "results": results}


@app.get("/playbooks", summary="List configured playbooks")
async def list_playbooks(
    principal=Depends(require_roles(principal_dep, ["soar:read"])),
) -> Dict[str, Any]:
    return {"playbooks": [p.model_dump() for p in engine.playbooks]}
