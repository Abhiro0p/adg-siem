from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
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

from .ad import create_decoy_user, disable_user, manage_group_membership
from .alerts import build_alert
from .audit import ActionAuditLogger, AuditMiddleware
from .auth import principal_dependency, require_roles, revoke_token
from .bus import InMemoryBus, RedisStreamBus
from .cmdb import fetch_assets
from .config import Settings
from .deception import BaselineTracker, coverage_map, realism_score
from .dns import DNSUpdater
from .dns_providers import CloudflareProvider, DNSProvider, PowerDNSProvider, RFC2136Provider, Route53Provider
from .enrichment import enrich_ip
from .health import run_readiness_checks
from .kill_chain import enrich_techniques
from .leader import LeaderElector
from .models import Event
from .orchestrator import DryRunOrchestrator, KubernetesOrchestrator, Orchestrator
from .policy import is_allowed, load_policy
from .rules import RuleEngine, actions_for_rule
from .secrets import load_vault_secrets
from .security import MTLSVerifier
from .siem import build_siem_emitter
from .state import StateStore
from .ttl import TTLReaper

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("adg.controller")
_handler = logging.StreamHandler()
_handler.setFormatter(jsonlogger.JsonFormatter())
logger.addHandler(_handler)
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Settings & Vault
# ---------------------------------------------------------------------------
settings = Settings()
vault_data = load_vault_secrets(settings)
for _key in ("jwt_secret", "dns_api_key", "alert_webhook_url", "siem_url", "siem_token",
             "abuseipdb_key", "otx_key", "siem_sentinel_workspace_id", "siem_sentinel_shared_key"):
    if _key in vault_data:
        setattr(settings, _key, vault_data[_key])

policy = load_policy(settings.policy_path)
mtls_verifier = MTLSVerifier(settings.mtls_required)
principal_dep = principal_dependency(settings.jwt_secret, settings.jwt_algorithm)

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Adaptive Deception Grid — Controller",
    version="2.0.0",
    description="Production-grade blue team deception orchestration platform.",
    openapi_tags=[
        {"name": "events", "description": "Ingest honeypot and network events"},
        {"name": "lures", "description": "Manage active honeypot deployments"},
        {"name": "rules", "description": "Detection rule management"},
        {"name": "intel", "description": "Enrichment and intelligence queries"},
        {"name": "ad", "description": "Active Directory decoy management"},
        {"name": "health", "description": "Service health and readiness"},
    ],
    dependencies=[Depends(mtls_verifier)],
)
app.add_middleware(AuditMiddleware, log_path=settings.audit_log_path)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.update({
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Cache-Control": "no-store",
        })
        return response


app.add_middleware(_SecurityHeadersMiddleware)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

if settings.admin_ui_enabled:
    import os
    if os.path.isdir("static"):
        app.mount("/ui", StaticFiles(directory="static", html=True), name="static")

# ---------------------------------------------------------------------------
# Core components
# ---------------------------------------------------------------------------
store = StateStore(settings.state_db_url)
action_audit = ActionAuditLogger(settings.action_audit_log_path)
approvers = [item.strip() for item in settings.approvers.split(",") if item.strip()]
rule_engine = RuleEngine.from_yaml(settings.rules_path, approvers)
baseline_tracker = BaselineTracker()

if settings.orchestration_mode == "kubernetes":
    orchestrator: Orchestrator = KubernetesOrchestrator(store)
else:
    orchestrator = DryRunOrchestrator(store)

bus = (
    InMemoryBus(settings.bus_queue_size)
    if settings.bus_mode == "in-memory"
    else RedisStreamBus(settings.redis_url)
)

if settings.dns_mode == "rfc2136":
    dns_provider: DNSProvider = RFC2136Provider(
        settings.dns_rfc2136_server,
        settings.dns_rfc2136_key_name,
        settings.dns_rfc2136_key_secret,
    )
elif settings.dns_mode == "route53":
    dns_provider = Route53Provider(settings.dns_route53_zone_id)
elif settings.dns_mode == "cloudflare":
    dns_provider = CloudflareProvider(settings.dns_cloudflare_zone_id, settings.dns_cloudflare_token)
else:
    dns_provider = PowerDNSProvider(settings.dns_api_url, settings.dns_api_key)

dns_updater = DNSUpdater(dns_provider)
siem_emitter = build_siem_emitter({
    "mode": settings.siem_mode,
    "url": settings.siem_url,
    "token": settings.siem_token,
    "index": settings.siem_index,
    "webhook_secret": settings.siem_webhook_secret,
    "workspace_id": settings.siem_sentinel_workspace_id,
    "shared_key": settings.siem_sentinel_shared_key,
    "site": settings.siem_datadog_site,
})

# ---------------------------------------------------------------------------
# OpenTelemetry
# ---------------------------------------------------------------------------
_resource = Resource(attributes={"service.name": "adg-controller", "service.version": "2.0.0"})
_otel_provider = TracerProvider(resource=_resource)
if settings.otlp_endpoint:
    _otel_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otlp_endpoint))
    )
trace.set_tracer_provider(_otel_provider)
FastAPIInstrumentor.instrument_app(app)
Instrumentator().instrument(app).expose(app)

# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.exception_handler(RateLimitExceeded)
async def _rate_limit(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(status_code=429, content={"error": "rate_limit_exceeded"})


@app.exception_handler(ValueError)
async def _value_error(request: Request, exc: ValueError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": "bad_request", "detail": str(exc)})


# ---------------------------------------------------------------------------
# Event processing
# ---------------------------------------------------------------------------

async def handle_event(event: Event) -> None:
    tracer = trace.get_tracer("adg.controller")
    with tracer.start_as_current_span("handle_event") as span:
        span.set_attribute("event.source", event.source)
        span.set_attribute("event.type", event.event_type)
        logger.info({"event": event.model_dump()})
        baseline_tracker.record(event.source)

        enrichment: Dict[str, Any] = {}
        _flat = {**event.model_extra, **event.data} if event.model_extra else event.data
        src_ip = _flat.get("src_ip")
        if settings.enrichment_enabled and src_ip:
            try:
                enrichment = await enrich_ip(src_ip, settings.abuseipdb_key, settings.otx_key)
            except Exception as exc:
                logger.warning("Enrichment failed for %s: %s", src_ip, exc)

        for rule in rule_engine.evaluate(event):
            action_audit.log_rule_fired(
                rule_name=rule.name,
                event_source=event.source,
                actions=[a.type for a in rule.actions],
                request_id=event.request_id,
            )
            for action in actions_for_rule(rule):
                await _dispatch_action(action, rule, event, enrichment)


async def _dispatch_action(action, rule, event: Event, enrichment: Dict[str, Any]) -> None:
    if action.type == "deploy_honeypot":
        subnet = action.params.get("subnet", "0.0.0.0/0")
        allowed = is_allowed(subnet, policy.get("allowed_subnets", []), policy.get("blocked_subnets", []))
        action_audit.log_honeypot_decision(
            rule_name=rule.name, subnet=subnet, allowed=allowed,
            reason="ok" if allowed else "policy", request_id=event.request_id,
        )
        if not allowed:
            logger.info({"policy_block": subnet, "rule": rule.name})
            return
        lure = await orchestrator.deploy(
            lure_type=action.params.get("lure_type", "cowrie"),
            subnet=subnet,
            ttl_seconds=int(action.params.get("ttl_seconds", 3600)),
            metadata=action.params,
        )
        if "dns" in action.params:
            dp = action.params["dns"]
            await dns_updater.upsert_record(
                zone=dp["zone"], name=dp["name"],
                record_type=dp.get("type", "A"), value=dp["value"],
                ttl=int(dp.get("ttl", 60)),
            )
        logger.info({"lure_deployed": lure.model_dump()})

    elif action.type == "emit_alert":
        alert = build_alert(rule, event, enrichment=enrichment)
        try:
            await siem_emitter.emit(alert)
            logger.info({"alert_emitted": alert.rule_name, "severity": alert.severity})
        except Exception as exc:
            logger.error({"alert_emit_failed": str(exc), "rule": rule.name})


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
_consumer_task: Optional[asyncio.Task] = None


@app.on_event("startup")
async def start_workers() -> None:
    global _consumer_task
    reaper = TTLReaper(store, orchestrator, settings.ttl_reap_interval)

    async def _start() -> None:
        global _consumer_task
        asyncio.create_task(reaper.run())
        _consumer_task = asyncio.create_task(_consume_bus())

    if settings.leader_election:
        elector = LeaderElector(
            settings.redis_url, settings.leader_lock_key, settings.leader_lock_ttl
        )

        def on_change(is_leader: bool) -> None:
            if is_leader:
                asyncio.create_task(_start())

        asyncio.create_task(elector.run(on_change))
    else:
        await _start()


@app.on_event("shutdown")
async def _shutdown() -> None:
    logger.info("Draining event bus before shutdown")
    await bus.close()
    if _consumer_task:
        _consumer_task.cancel()
        try:
            await _consumer_task
        except asyncio.CancelledError:
            pass


async def _consume_bus() -> None:
    async for event in bus.subscribe():
        try:
            await handle_event(event)
        except Exception as exc:
            logger.error("Event handling error: %s", exc, exc_info=True)


# ---------------------------------------------------------------------------
# Routes — health
# ---------------------------------------------------------------------------

@app.get("/health/live", tags=["health"], summary="Liveness probe")
async def health_live() -> Dict[str, str]:
    return {"status": "ok"}


@app.get("/health/ready", tags=["health"], summary="Readiness probe — checks all dependencies")
async def health_ready() -> JSONResponse:
    result = await run_readiness_checks(
        db_url=settings.state_db_url,
        redis_url=settings.redis_url if settings.bus_mode == "redis" else "",
        vault_addr=settings.vault_addr,
        vault_token=settings.vault_token,
        siem_url=settings.siem_url,
    )
    return JSONResponse(content=result, status_code=200 if result["ready"] else 503)


@app.get("/health", tags=["health"], include_in_schema=False)
async def health_legacy() -> Dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Routes — events
# ---------------------------------------------------------------------------

@app.post("/events", tags=["events"], summary="Ingest a network or honeypot event")
@limiter.limit(settings.rate_limit)
async def ingest_event(
    request: Request,
    event: Event,
    principal=Depends(require_roles(principal_dep, ["controller:write"])),
) -> Dict[str, str]:
    event.request_id = getattr(request.state, "request_id", None)
    await bus.publish(event)
    return {"status": "queued"}


# ---------------------------------------------------------------------------
# Routes — lures
# ---------------------------------------------------------------------------

@app.get("/lures", tags=["lures"], summary="List active lure deployments")
async def lures(principal=Depends(require_roles(principal_dep, ["controller:read"]))):
    return [lure.model_dump() for lure in store.list_lures()]


# ---------------------------------------------------------------------------
# Routes — rules
# ---------------------------------------------------------------------------

@app.get("/rules", tags=["rules"], summary="List loaded detection rules")
async def list_rules(principal=Depends(require_roles(principal_dep, ["controller:read"]))):
    return [rule.model_dump() for rule in rule_engine.rules]


@app.post("/rules/reload", tags=["rules"], summary="Hot-reload rules from disk")
async def reload_rules(
    principal=Depends(require_roles(principal_dep, ["controller:admin"])),
) -> Dict[str, Any]:
    global rule_engine
    rule_engine = RuleEngine.from_yaml(settings.rules_path, approvers)
    action_audit.log("rules_reload", principal.subject, settings.rules_path, "ok")
    return {"status": "reloaded", "count": len(rule_engine.rules)}


# ---------------------------------------------------------------------------
# Routes — intelligence
# ---------------------------------------------------------------------------

@app.post("/enrich/ip", tags=["intel"], summary="Enrich an IP with GeoIP + threat intel")
async def enrich_ip_route(
    ip: str,
    principal=Depends(require_roles(principal_dep, ["controller:read"])),
) -> Dict[str, Any]:
    return await enrich_ip(ip, settings.abuseipdb_key, settings.otx_key)


@app.post("/realism", tags=["intel"], summary="Score an event for deception realism")
async def score_realism(
    event: Event,
    principal=Depends(require_roles(principal_dep, ["controller:read"])),
) -> Dict[str, Any]:
    return realism_score(event)


@app.post("/coverage", tags=["intel"], summary="Compute coverage map from event list")
async def get_coverage(
    events: List[Event],
    principal=Depends(require_roles(principal_dep, ["controller:read"])),
) -> Dict[str, Any]:
    return coverage_map(events)


@app.get("/techniques/{technique_id}", tags=["intel"], summary="Look up a MITRE ATT&CK technique")
async def technique_detail(
    technique_id: str,
    principal=Depends(require_roles(principal_dep, ["controller:read"])),
) -> Dict[str, Any]:
    details = enrich_techniques([technique_id])
    if not details or details[0].get("tactic") == "unknown":
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return details[0]


# ---------------------------------------------------------------------------
# Routes — CMDB
# ---------------------------------------------------------------------------

@app.get("/cmdb/assets", tags=["lures"], summary="Query CMDB asset inventory")
async def cmdb_assets(
    subnet: Optional[str] = None,
    principal=Depends(require_roles(principal_dep, ["controller:read"])),
):
    if not settings.cmdb_url:
        return []
    return fetch_assets(settings.cmdb_url, settings.cmdb_token, subnet)


# ---------------------------------------------------------------------------
# Routes — Active Directory
# ---------------------------------------------------------------------------

@app.post("/ad/decoy", tags=["ad"], summary="Create an AD decoy user account")
async def create_ad_decoy(
    account_name: str,
    ou: str = "",
    principal=Depends(require_roles(principal_dep, ["controller:admin"])),
):
    create_decoy_user(
        settings.ad_server, settings.ad_user, settings.ad_password,
        settings.ad_base_dn, account_name, ou=ou,
        attributes={"sAMAccountName": account_name, "userPrincipalName": f"{account_name}@local"},
    )
    action_audit.log("ad_decoy_create", principal.subject, account_name, "ok")
    return {"status": "created"}


@app.post("/ad/disable", tags=["ad"], summary="Disable an AD decoy account")
async def disable_ad_decoy(
    account_name: str,
    principal=Depends(require_roles(principal_dep, ["controller:admin"])),
):
    disable_user(
        settings.ad_server, settings.ad_user, settings.ad_password,
        settings.ad_base_dn, account_name,
    )
    action_audit.log("ad_decoy_disable", principal.subject, account_name, "ok")
    return {"status": "disabled"}


@app.post("/ad/group", tags=["ad"], summary="Add or remove a decoy account from an AD group")
async def manage_ad_group(
    account_name: str,
    group_dn: str,
    add: bool = True,
    principal=Depends(require_roles(principal_dep, ["controller:admin"])),
):
    manage_group_membership(
        settings.ad_server, settings.ad_user, settings.ad_password,
        settings.ad_base_dn, account_name, group_dn, add=add,
    )
    action_audit.log(
        "ad_group_membership", principal.subject,
        f"{account_name}:{group_dn}", "added" if add else "removed",
    )
    return {"status": "added" if add else "removed"}


# ---------------------------------------------------------------------------
# Routes — token revocation
# ---------------------------------------------------------------------------

@app.post("/auth/revoke", tags=["health"], summary="Revoke a JWT by JTI")
async def revoke_jwt(
    jti: str,
    exp: float,
    principal=Depends(require_roles(principal_dep, ["controller:admin"])),
) -> Dict[str, str]:
    revoke_token(jti, exp)
    action_audit.log("token_revoke", principal.subject, jti, "ok")
    return {"status": "revoked"}

