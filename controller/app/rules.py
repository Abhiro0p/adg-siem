from __future__ import annotations

import ipaddress
import re
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Any, Deque, Dict, Iterable, List, Optional

import yaml

from .models import Action, Condition, ConditionGroup, Event, Rule
from .utils import get_field


# ---------------------------------------------------------------------------
# Sliding-window counter for stateful threshold detection
# ---------------------------------------------------------------------------

class _WindowCounter:
    def __init__(self) -> None:
        self._windows: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def record(self, key: str, now: float) -> None:
        with self._lock:
            self._windows[key].append(now)

    def count_in_window(self, key: str, window_seconds: int, now: float) -> int:
        with self._lock:
            dq = self._windows[key]
            cutoff = now - window_seconds
            while dq and dq[0] < cutoff:
                dq.popleft()
            return len(dq)


_window_counter = _WindowCounter()


# ---------------------------------------------------------------------------
# Operator table
# ---------------------------------------------------------------------------

def _eq(v: Any, t: Any) -> bool:    return v == t
def _neq(v: Any, t: Any) -> bool:   return v != t
def _contains(v: Any, t: Any) -> bool:
    return t is not None and str(t) in str(v or "")
def _ncontains(v: Any, t: Any) -> bool: return not _contains(v, t)
def _sw(v: Any, t: Any) -> bool:    return str(v or "").startswith(str(t or ""))
def _ew(v: Any, t: Any) -> bool:    return str(v or "").endswith(str(t or ""))
def _regex(v: Any, t: Any) -> bool: return v is not None and re.search(str(t), str(v)) is not None
def _in_list(v: Any, t: Any) -> bool:
    return isinstance(t, list) and v in t
def _nin_list(v: Any, t: Any) -> bool: return not _in_list(v, t)
def _in_subnet(v: Any, t: Any) -> bool:
    try:
        return ipaddress.ip_address(str(v)) in ipaddress.ip_network(str(t), strict=False)
    except ValueError:
        return False
def _nin_subnet(v: Any, t: Any) -> bool: return not _in_subnet(v, t)
def _cidr_overlap(v: Any, t: Any) -> bool:
    try:
        return ipaddress.ip_network(str(v), strict=False).overlaps(
            ipaddress.ip_network(str(t), strict=False)
        )
    except ValueError:
        return False
def _gt(v: Any, t: Any) -> bool:    return v is not None and v > t
def _lt(v: Any, t: Any) -> bool:    return v is not None and v < t
def _gte(v: Any, t: Any) -> bool:   return v is not None and v >= t
def _lte(v: Any, t: Any) -> bool:   return v is not None and v <= t
def _range(v: Any, t: Any) -> bool:
    return isinstance(t, (list, tuple)) and len(t) == 2 and v is not None and t[0] <= v <= t[1]
def _exists(v: Any, _: Any) -> bool:    return v is not None
def _nexists(v: Any, _: Any) -> bool:   return v is None

_OPERATORS = {
    "equals": _eq, "not_equals": _neq,
    "contains": _contains, "not_contains": _ncontains,
    "starts_with": _sw, "ends_with": _ew,
    "regex": _regex,
    "in_list": _in_list, "not_in_list": _nin_list,
    "in_subnet": _in_subnet, "not_in_subnet": _nin_subnet,
    "cidr_overlap": _cidr_overlap,
    "gt": _gt, "lt": _lt, "gte": _gte, "lte": _lte, "range": _range,
    "exists": _exists, "not_exists": _nexists,
    "threshold": None,  # handled specially
}

_VALID_OPERATORS: frozenset[str] = frozenset(_OPERATORS.keys())
_REQUIRED_RULE_FIELDS = {"name", "when", "actions"}


# ---------------------------------------------------------------------------
# Rule engine
# ---------------------------------------------------------------------------

class RuleEngine:
    def __init__(self, rules: List[Rule], required_approvers: Optional[List[str]] = None) -> None:
        self.rules = rules
        self.required_approvers = required_approvers or []

    @classmethod
    def from_yaml(cls, path: str, required_approvers: Optional[List[str]] = None) -> "RuleEngine":
        with open(path, "r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
        _validate_schema(payload)
        rules = [Rule(**item) for item in payload.get("rules", [])]
        return cls(rules, required_approvers)

    def evaluate(self, event: Event) -> Iterable[Rule]:
        for rule in self.rules:
            if rule.enabled and self._approved(rule) and self._match(rule, event):
                yield rule

    # ------------------------------------------------------------------

    def _approved(self, rule: Rule) -> bool:
        if not self.required_approvers:
            return True
        return getattr(rule, "approved_by", None) in self.required_approvers

    def _match(self, rule: Rule, event: Event) -> bool:
        if rule.condition_groups:
            return self._match_groups(rule.condition_groups, event)
        return all(self._eval_condition(c, event) for c in rule.when)

    def _match_groups(self, groups: List[ConditionGroup], event: Event) -> bool:
        for group in groups:
            results = [self._eval_condition(c, event) for c in group.conditions]
            passed = any(results) if group.logic.lower() == "or" else all(results)
            if not passed:
                return False
        return True

    def _eval_condition(self, condition: Condition, event: Event) -> bool:
        if condition.op.lower() == "threshold":
            return self._eval_threshold(condition, event)

        value = get_field({**event.model_dump(), "data": event.data}, condition.field)
        op_fn = _OPERATORS.get(condition.op.lower())
        if op_fn is None:
            raise ValueError(f"Unsupported operator: {condition.op!r}")
        return op_fn(value, condition.value)

    def _eval_threshold(self, condition: Condition, event: Event) -> bool:
        """
        Fires when key_field appears >= count times in window_seconds.
        condition.value: {key_field: str, count: int, window_seconds: int}
        """
        params = condition.value or {}
        count_target: int = int(params.get("count", 1))
        window: int = int(params.get("window_seconds", 60))
        key_field: str = str(params.get("key_field", condition.field))

        raw = {**event.model_dump(), "data": event.data}
        key_value = get_field(raw, key_field)
        window_key = f"{condition.field}:{key_value}"

        now = time.time()
        _window_counter.record(window_key, now)
        return _window_counter.count_in_window(window_key, window, now) >= count_target


def actions_for_rule(rule: Rule) -> List[Action]:
    return rule.actions


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

def _validate_schema(payload: dict) -> None:
    if not isinstance(payload, dict):
        raise ValueError("Rules YAML must be a mapping")
    rules = payload.get("rules", [])
    if not isinstance(rules, list):
        raise ValueError("'rules' must be a list")
    for i, rule in enumerate(rules):
        missing = _REQUIRED_RULE_FIELDS - set(rule.keys())
        if missing:
            raise ValueError(f"Rule[{i}] missing: {missing}")
        for j, cond in enumerate(rule.get("when", [])):
            op = cond.get("op", "")
            if op not in _VALID_OPERATORS:
                raise ValueError(
                    f"Rule[{i}] condition[{j}]: unknown operator {op!r}. "
                    f"Valid: {sorted(_VALID_OPERATORS)}"
                )
