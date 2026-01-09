from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class Event(BaseModel):
    model_config = ConfigDict(extra="allow")

    source: str = "unknown"
    event_type: str
    ts: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    data: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class Condition(BaseModel):
    field: str
    op: str
    value: Optional[Any] = None


class ConditionGroup(BaseModel):
    logic: Literal["and", "or"] = "and"
    conditions: List[Condition] = Field(default_factory=list)


class Action(BaseModel):
    type: str
    params: Dict[str, Any] = Field(default_factory=dict)


class Rule(BaseModel):
    name: str
    enabled: bool = True
    when: List[Condition] = Field(default_factory=list)
    condition_groups: List[ConditionGroup] = Field(default_factory=list)
    actions: List[Action]
    mitre: List[str] = Field(default_factory=list)
    severity: str = "medium"
    approved_by: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class LureDeployment(BaseModel):
    lure_id: str
    lure_type: str
    subnet: str
    hostname: str
    created_at: datetime
    ttl_seconds: int
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertPayload(BaseModel):
    rule_name: str
    severity: str = "medium"
    event: Event
    mitre: List[str]
    kill_chain: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    session_id: Optional[str] = None
    pcap_path: Optional[str] = None
    transcript: Optional[str] = None
    enrichment: Dict[str, Any] = Field(default_factory=dict)
    extra: Dict[str, Any] = Field(default_factory=dict)
