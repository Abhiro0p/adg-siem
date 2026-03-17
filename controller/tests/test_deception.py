from datetime import datetime, timezone

from app.deception import BaselineTracker, coverage_map, realism_score
from app.models import Event


def _event(**data) -> Event:
    return Event(source="test", event_type="scan", ts=datetime.now(timezone.utc), data=data)


def test_realism_score_returns_dict():
    result = realism_score(_event(port=22, src_ip="1.2.3.4", credential="admin", user_agent="nmap"))
    assert "score" in result
    assert "confidence" in result
    assert "breakdown" in result
    assert "label" in result


def test_realism_score_high_value_port_boosts():
    low = realism_score(_event())["score"]
    high = realism_score(_event(port=22, src_ip="1.2.3.4"))["score"]
    assert high > low


def test_realism_label_values():
    result = realism_score(_event())
    assert result["label"] in {"low", "medium", "high"}


def test_realism_scanner_ua_boosts_behaviour():
    without = realism_score(_event())["breakdown"]["behaviour"]
    with_ua = realism_score(_event(user_agent="masscan/1.0"))["breakdown"]["behaviour"]
    assert with_ua > without


def test_coverage_map_groups_by_subnet():
    events = [_event(subnet="10.0.0.0/24"), _event(subnet="10.0.0.0/24"), _event(subnet="10.0.1.0/24")]
    result = coverage_map(events)
    assert result["by_subnet"]["10.0.0.0/24"] == 2
    assert result["by_subnet"]["10.0.1.0/24"] == 1
    assert result["total"] == 3


def test_coverage_map_by_event_type():
    e1, e2 = _event(), _event()
    e1.event_type = "scan"
    e2.event_type = "auth"
    result = coverage_map([e1, e2])
    assert "scan" in result["by_event_type"]
    assert "auth" in result["by_event_type"]


def test_baseline_tracker_records_events():
    tracker = BaselineTracker()
    result = tracker.record("test-source")
    assert result["event_count"] >= 1
    assert result["source"] == "test-source"
