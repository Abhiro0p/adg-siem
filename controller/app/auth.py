from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Callable, Dict, Iterable, List, Optional, Set

import jwt
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# ---------------------------------------------------------------------------
# Token blacklist — in-memory with TTL purge.  Replace with Redis for HA.
# ---------------------------------------------------------------------------
_blacklist: Set[str] = set()
_blacklist_expiry: Dict[str, float] = {}
_blacklist_lock = Lock()


def revoke_token(jti: str, exp: float) -> None:
    with _blacklist_lock:
        _blacklist.add(jti)
        _blacklist_expiry[jti] = exp


def _is_revoked(jti: str) -> bool:
    with _blacklist_lock:
        now = time.time()
        expired = [k for k, v in _blacklist_expiry.items() if v < now]
        for k in expired:
            _blacklist.discard(k)
            _blacklist_expiry.pop(k, None)
        return jti in _blacklist


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------

@dataclass
class Principal:
    subject: str
    roles: List[str]
    jti: str = field(default="")
    exp: float = field(default=0.0)


security_scheme = HTTPBearer(auto_error=False)

_REQUIRED_CLAIMS = ["sub", "exp", "iat", "jti"]


def _decode_token(token: str, secret: str, algorithm: str) -> dict:
    return jwt.decode(
        token,
        secret,
        algorithms=[algorithm],
        options={"require": _REQUIRED_CLAIMS},
    )


def authenticate(
    credentials: Optional[HTTPAuthorizationCredentials],
    secret: str,
    algorithm: str,
) -> Principal:
    if credentials is None or credentials.credentials is None:
        raise HTTPException(status_code=401, detail="Missing credentials")
    if not secret:
        raise HTTPException(status_code=500, detail="Auth secret not configured")

    try:
        payload = _decode_token(credentials.credentials, secret, algorithm)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail=f"Invalid token: {exc}")

    jti: str = str(payload.get("jti", ""))
    exp: float = float(payload.get("exp", 0))

    if _is_revoked(jti):
        raise HTTPException(status_code=401, detail="Token has been revoked")

    subject: str = payload.get("sub", "unknown")
    roles: List[str] = payload.get("roles", [])
    return Principal(subject=subject, roles=list(roles), jti=jti, exp=exp)


def principal_dependency(secret: str, algorithm: str) -> Callable:
    def _principal(
        credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme),
    ) -> Principal:
        return authenticate(credentials, secret, algorithm)

    return _principal


def require_roles(principal_dep: Callable, *required: Iterable[str]):
    required_set = {role for roles in required for role in roles}

    def _require(principal: Principal = Depends(principal_dep)):
        if not required_set.intersection(set(principal.roles)):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return principal

    return _require
