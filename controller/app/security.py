from __future__ import annotations

from fastapi import HTTPException, Request


_EXEMPT_PREFIXES = ("/health", "/metrics", "/docs", "/openapi", "/redoc")


class MTLSVerifier:
    def __init__(self, required: bool = True) -> None:
        self.required = required

    async def __call__(self, request: Request) -> None:
        if not self.required:
            return
        if any(request.url.path.startswith(p) for p in _EXEMPT_PREFIXES):
            return
        verified = request.headers.get("X-SSL-Client-Verify")
        if verified != "SUCCESS":
            raise HTTPException(status_code=401, detail="mTLS verification failed")

