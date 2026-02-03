from __future__ import annotations

import base64
import json
import random
import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from faker import Faker

from .models import Token

faker = Faker()

# Character sets matching real-world token formats
_B62 = string.ascii_letters + string.digits
_HEX = string.hexdigits[:16]
_UPPER_ALNUM = string.ascii_uppercase + string.digits


def _rand(charset: str, n: int) -> str:
    return "".join(secrets.choice(charset) for _ in range(n))


# ---------------------------------------------------------------------------
# Token type generators — each returns a (value, metadata) tuple
# ---------------------------------------------------------------------------

def _ssh_key() -> tuple[str, Dict[str, Any]]:
    user = faker.user_name()
    host = faker.domain_name()
    # Realistic-length base64 blob (actual RSA public key is ~372 chars base64)
    blob = base64.b64encode(secrets.token_bytes(279)).decode()
    value = f"ssh-rsa {blob} {user}@{host}"
    return value, {"key_type": "rsa", "bits": 2048, "comment": f"{user}@{host}"}


def _aws_access_key() -> tuple[str, Dict[str, Any]]:
    # Real AWS access keys: AKIA + 16 uppercase alphanumeric chars
    key_id = "AKIA" + _rand(_UPPER_ALNUM, 16)
    secret = base64.b64encode(secrets.token_bytes(30)).decode().rstrip("=")
    value = key_id
    return value, {"aws_secret_access_key": secret, "region": faker.random_element(["us-east-1", "eu-west-1", "ap-southeast-2"])}


def _aws_session_token() -> tuple[str, Dict[str, Any]]:
    # STS session token format
    value = "FwoGZXIvYXdzE" + base64.b64encode(secrets.token_bytes(200)).decode().replace("\n", "")
    return value, {"type": "sts_session_token", "duration_hours": 12}


def _azure_service_principal() -> tuple[str, Dict[str, Any]]:
    client_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())
    client_secret = base64.b64encode(secrets.token_bytes(32)).decode()
    value = json.dumps({
        "clientId": client_id,
        "clientSecret": client_secret,
        "subscriptionId": str(uuid.uuid4()),
        "tenantId": tenant_id,
    })
    return value, {"credential_type": "service_principal"}


def _gcp_service_account() -> tuple[str, Dict[str, Any]]:
    project = f"project-{faker.bothify('??####')}"
    sa_email = f"{faker.user_name()}@{project}.iam.gserviceaccount.com"
    private_key_id = secrets.token_hex(20)
    # Fake PEM structure (not a valid key but looks real)
    fake_key_body = base64.b64encode(secrets.token_bytes(1700)).decode()
    pem = f"-----BEGIN RSA PRIVATE KEY-----\n{fake_key_body[:64]}\n-----END RSA PRIVATE KEY-----\n"
    value = json.dumps({
        "type": "service_account",
        "project_id": project,
        "private_key_id": private_key_id,
        "private_key": pem,
        "client_email": sa_email,
        "client_id": str(random.randint(10**17, 10**18 - 1)),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    return value, {"project": project, "service_account": sa_email}


def _browser_password() -> tuple[str, Dict[str, Any]]:
    password = faker.password(length=random.randint(10, 20), special_chars=True, digits=True, upper_case=True)
    return password, {"username": faker.user_name(), "url": f"https://{faker.domain_name()}"}


def _rdp_history() -> tuple[str, Dict[str, Any]]:
    ip = faker.ipv4_private()
    return f"TERMSRV/{ip}", {"hostname": faker.hostname(), "port": 3389}


def _env_api_key() -> tuple[str, Dict[str, Any]]:
    prefix = faker.random_element(["sk", "pk", "api", "key", "tok"])
    value = f"{prefix}_{secrets.token_urlsafe(32)}"
    return value, {"variable_name": "API_KEY", "service": faker.domain_name()}


def _github_pat() -> tuple[str, Dict[str, Any]]:
    value = "ghp_" + _rand(_B62, 36)
    return value, {"scopes": ["repo", "read:org"], "expiry_days": 90}


def _slack_token() -> tuple[str, Dict[str, Any]]:
    value = "xoxb-" + "-".join(_rand(string.digits, n) for n in [10, 10, 24])
    return value, {"type": "bot_token"}


def _k8s_service_account_token() -> tuple[str, Dict[str, Any]]:
    header = base64.b64encode(json.dumps({"alg": "RS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.b64encode(json.dumps({
        "iss": "kubernetes/serviceaccount",
        "namespace": faker.random_element(["default", "kube-system", "monitoring"]),
        "serviceaccountname": f"svc-{faker.user_name()}",
        "sub": f"system:serviceaccount:default:{faker.user_name()}",
    }).encode()).decode().rstrip("=")
    sig = base64.b64encode(secrets.token_bytes(256)).decode().rstrip("=")
    value = f"{header}.{payload}.{sig}"
    return value, {"type": "kubernetes_service_account_token"}


def _git_credential() -> tuple[str, Dict[str, Any]]:
    host = faker.random_element(["github.com", "gitlab.com", "bitbucket.org"])
    username = faker.user_name()
    password = secrets.token_urlsafe(20)
    value = f"https://{username}:{password}@{host}"
    return value, {"host": host, "format": "git_credential_helper"}


def _docker_config() -> tuple[str, Dict[str, Any]]:
    registry = faker.random_element(["registry.hub.docker.com", "gcr.io", "ghcr.io"])
    auth = base64.b64encode(f"{faker.user_name()}:{secrets.token_urlsafe(20)}".encode()).decode()
    value = json.dumps({
        "auths": {registry: {"auth": auth}},
        "HttpHeaders": {"User-Agent": "Docker-Client/24.0.0"},
    })
    return value, {"registry": registry, "type": "docker_config_json"}


def _database_connection_string() -> tuple[str, Dict[str, Any]]:
    db_type = faker.random_element(["postgresql", "mysql", "mongodb"])
    user = faker.user_name()
    password = faker.password(length=16)
    host = f"db.{faker.domain_name()}"
    db = faker.word()
    if db_type == "mongodb":
        value = f"mongodb+srv://{user}:{password}@{host}/{db}?retryWrites=true&w=majority"
    else:
        value = f"{db_type}://{user}:{password}@{host}:5432/{db}"
    return value, {"db_type": db_type, "host": host}


def _aws_cli_config() -> tuple[str, Dict[str, Any]]:
    key_id = "AKIA" + _rand(_UPPER_ALNUM, 16)
    secret = base64.b64encode(secrets.token_bytes(30)).decode().rstrip("=")
    region = faker.random_element(["us-east-1", "eu-west-1", "ap-southeast-1"])
    value = (
        f"[default]\n"
        f"aws_access_key_id = {key_id}\n"
        f"aws_secret_access_key = {secret}\n"
        f"region = {region}\n"
    )
    return value, {"format": "aws_credentials_file", "region": region}


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_GENERATORS = {
    "ssh_key": _ssh_key,
    "aws_key": _aws_access_key,
    "aws_session_token": _aws_session_token,
    "azure_key": _azure_service_principal,
    "gcp_key": _gcp_service_account,
    "browser_password": _browser_password,
    "rdp_history": _rdp_history,
    "env_api_key": _env_api_key,
    "github_pat": _github_pat,
    "slack_token": _slack_token,
    "k8s_token": _k8s_service_account_token,
    "git_credential": _git_credential,
    "docker_config": _docker_config,
    "db_connection_string": _database_connection_string,
    "aws_cli_config": _aws_cli_config,
}

SUPPORTED_TOKEN_TYPES = sorted(_GENERATORS.keys())


def generate_token(token_type: str, ttl_hours: Optional[int] = None) -> Token:
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(hours=ttl_hours) if ttl_hours else None

    generator = _GENERATORS.get(token_type)
    if generator is None:
        raise ValueError(f"Unknown token type {token_type!r}. Valid types: {SUPPORTED_TOKEN_TYPES}")

    value, extra_meta = generator()

    return Token(
        token_id=str(uuid.uuid4()),
        token_type=token_type,
        value=value,
        created_at=created_at,
        expires_at=expires_at,
        metadata={"source": "token-engine", **extra_meta},
    )
