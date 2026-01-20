from __future__ import annotations

from typing import Any, Dict

from .kill_chain import enrich_techniques, kill_chain_for
from .models import AlertPayload, Event, Rule
from .redaction import redact_dict


def build_alert(
    rule: Rule,
    event: Event,
    enrichment: Dict[str, Any] | None = None,
) -> AlertPayload:
    technique_details = enrich_techniques(rule.mitre)
    return AlertPayload(
        rule_name=rule.name,
        severity=rule.severity,
        event=event.model_copy(update={"data": redact_dict(event.data)}),
        mitre=rule.mitre,
        kill_chain=kill_chain_for(rule.mitre),
        tags=rule.tags,
        enrichment=enrichment or {},
        extra={
            "source": event.source,
            "techniques": technique_details,
        },
    )
