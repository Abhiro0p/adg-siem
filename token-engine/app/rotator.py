from __future__ import annotations

from typing import List

from .generator import generate_token
from .store import TokenStore


def rotate_tokens(store: TokenStore, token_types: List[str], ttl_hours: int | None = None):
    tokens = []
    for token_type in token_types:
        token = generate_token(token_type, ttl_hours)
        store.add_token(token)
        tokens.append(token)
    return tokens
