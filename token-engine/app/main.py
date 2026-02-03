from __future__ import annotations

import logging

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace import TracerProvider
from prometheus_fastapi_instrumentator import Instrumentator
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pythonjsonlogger import jsonlogger
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.responses import JSONResponse

from .audit import AuditMiddleware
from .auth import principal_dependency, require_roles
from .config import Settings
from .decoy_files import build_decoy_bundle
from .emitters import WebhookEmitter
from .generator import generate_token
from .models import TokenAccess
from .rotator import rotate_tokens
from .secrets import load_vault_secrets
from .security import MTLSVerifier
from .store import TokenStore

settings = Settings()
vault_data = load_vault_secrets(settings)
if "jwt_secret" in vault_data:
    settings.jwt_secret = vault_data["jwt_secret"]
if "webhook_url" in vault_data:
    settings.webhook_url = vault_data["webhook_url"]

mtls_verifier = MTLSVerifier(settings.mtls_required)
principal_dep = principal_dependency(settings.jwt_secret, settings.jwt_algorithm)
app = FastAPI(title="Honeytoken Engine", dependencies=[Depends(mtls_verifier)])
app.add_middleware(AuditMiddleware, log_path=settings.audit_log_path)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
store = TokenStore(settings.db_path)
emitter = WebhookEmitter(settings.webhook_url)

logger = logging.getLogger("adg.token-engine")
handler = logging.StreamHandler()
handler.setFormatter(jsonlogger.JsonFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

resource = Resource(attributes={"service.name": "token-engine"})
provider = TracerProvider(resource=resource)
if settings.otlp_endpoint:
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=settings.otlp_endpoint)))
trace.set_tracer_provider(provider)
FastAPIInstrumentor.instrument_app(app)
Instrumentator().instrument(app).expose(app)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request, exc):
    return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/tokens")
@limiter.limit(settings.rate_limit)
async def create_token(
    request: Request,
    token_type: str,
    ttl_hours: int | None = None,
    principal=Depends(require_roles(principal_dep, ["token:write"])),
):
    token = generate_token(token_type, ttl_hours)
    store.add_token(token)
    return token.model_dump()


@app.get("/tokens")
async def list_tokens(principal=Depends(require_roles(principal_dep, ["token:read"]))):
    return [token.model_dump() for token in store.list_tokens()]


@app.post("/access/{token_id}")
@limiter.limit(settings.rate_limit)
async def access_token(
    request: Request,
    token_id: str,
    user_agent: str | None = Header(default=None),
    principal=Depends(require_roles(principal_dep, ["token:write"])),
):
    token = store.get_token(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    access = TokenAccess(token_id=token_id, src_ip=None, user_agent=user_agent)
    store.add_access(access)
    await emitter.emit(access)
    logger.info({"access": access.model_dump()})
    return {"status": "logged"}


@app.post("/rotate")
async def rotate(
    token_types: list[str],
    ttl_hours: int | None = None,
    principal=Depends(require_roles(principal_dep, ["token:admin"])),
):
    tokens = rotate_tokens(store, token_types, ttl_hours)
    return [token.model_dump() for token in tokens]


@app.get("/bundle")
async def bundle(principal=Depends(require_roles(principal_dep, ["token:read"]))):
    return build_decoy_bundle()
