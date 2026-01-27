from __future__ import annotations

from typing import Any, Dict


def get_field(data: Dict[str, Any], path: str) -> Any:
    parts = path.split(".")
    current: Any = data
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current
