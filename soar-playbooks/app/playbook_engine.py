from __future__ import annotations

from typing import Dict, List

import yaml

from .models import Alert, Playbook
from .responses import ResponseActions


class PlaybookEngine:
    def __init__(self, playbooks: List[Playbook], actions: ResponseActions) -> None:
        self.playbooks = playbooks
        self.actions = actions

    @classmethod
    def from_yaml(cls, path: str, actions: ResponseActions) -> "PlaybookEngine":
        with open(path, "r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
        playbooks = [Playbook(**item) for item in payload.get("playbooks", [])]
        return cls(playbooks, actions)

    async def handle_alert(self, alert: Alert) -> Dict[str, str]:
        results: Dict[str, str] = {}
        for playbook in self.playbooks:
            if not playbook.on_alert:
                continue
            for step in playbook.steps:
                result = await self.actions.execute(step.action, alert, step.params)
                results[f"{playbook.name}:{step.action}"] = result
        return results
