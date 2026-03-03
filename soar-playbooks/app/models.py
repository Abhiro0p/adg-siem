from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Alert(BaseModel):
    rule_name: str
    ts: datetime = Field(default_factory=datetime.utcnow)
    source_ip: Optional[str] = None
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PlaybookStep(BaseModel):
    action: str
    params: Dict[str, Any] = Field(default_factory=dict)


class Playbook(BaseModel):
    name: str
    on_alert: bool = True
    steps: List[PlaybookStep]
