from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

# Field names that always get redacted regardless of value
SENSITIVE_FIELD_NAMES: frozenset[str] = frozenset({
    "password", "passwd", "pass", "pwd",
    "secret", "secret_key", "client_secret",
    "token", "access_token", "refresh_token", "id_token", "bearer",
    "api_key", "apikey", "api_secret",
    "auth", "authorization", "x-api-key",
    "private_key", "private_key_id", "ssh_key", "pem",
    "credential", "credentials",
    "ssn", "social_security",
    "credit_card", "card_number", "cvv", "cvc",
    "connection_string", "db_password", "database_password",
    "aws_secret_access_key", "aws_session_token",
    "client_id", "client_secret",
})

# Regex patterns that match sensitive values regardless of field name
_VALUE_PATTERNS: List[re.Pattern[str]] = [
    re.compile(r"\bAKIA[0-9A-Z]{16,}\b"),                        # AWS access key (16+ chars)
    re.compile(r"(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY"),  # PEM key
    re.compile(r"(?i)ghp_[A-Za-z0-9]{36}"),                      # GitHub PAT
    re.compile(r"(?i)glpat-[A-Za-z0-9\-]{20}"),                  # GitLab PAT
    re.compile(r"(?i)xox[baprs]-[0-9A-Za-z\-]+"),                # Slack token
    re.compile(r"(?i)eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),  # JWT
    re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*"),           # Bearer token
    re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"),  # Credit card
]


def _contains_sensitive_value(value: str) -> bool:
    for pattern in _VALUE_PATTERNS:
        if pattern.search(value):
            return True
    return False


def redact_dict(
    payload: Dict[str, Any],
    extra_fields: Iterable[str] = (),
) -> Dict[str, Any]:
    blocked = SENSITIVE_FIELD_NAMES | {f.lower() for f in extra_fields}
    return _redact(payload, blocked)


def _redact(obj: Any, blocked: frozenset[str] | set[str]) -> Any:
    if isinstance(obj, dict):
        result: Dict[str, Any] = {}
        for key, value in obj.items():
            if key.lower() in blocked:
                result[key] = "[REDACTED]"
            else:
                result[key] = _redact(value, blocked)
        return result
    if isinstance(obj, list):
        return [_redact(item, blocked) for item in obj]
    if isinstance(obj, str) and _contains_sensitive_value(obj):
        return "[REDACTED]"
    return obj
