from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class Token(BaseModel):
    token_id: str
    token_type: str
    value: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TokenAccess(BaseModel):
    token_id: str
    accessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: Optional[str] = None
    user_agent: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)
