from datetime import datetime, timezone

import pytest

from app.models import Event
from app.rules import RuleEngine


def _make_event(**data) -> Event:
    return Event(source="test", event_type="test", ts=datetime.now(timezone.utc), data=data)


def _engine(tmp_path, content: str) -> RuleEngine:
    f = tmp_path / "rules.yaml"
    f.write_text(content)
    return RuleEngine.from_yaml(str(f))


def test_rule_matches_port_scan(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: test
    enabled: true
    when:
      - field: event_type
        op: equals
        value: port_scan
      - field: data.port
        op: equals
        value: 8080
    actions:
      - type: emit_alert
        params: {}
""")
    e = _make_event(port=8080)
    e.event_type = "port_scan"
    assert len(list(engine.evaluate(e))) == 1


def test_rule_no_match(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: test
    enabled: true
    when:
      - field: event_type
        op: equals
        value: port_scan
    actions:
      - type: emit_alert
        params: {}
""")
    e = _make_event()
    e.event_type = "auth"
    assert list(engine.evaluate(e)) == []


def test_not_equals_operator(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: test
    enabled: true
    when:
      - field: data.status
        op: not_equals
        value: ok
    actions:
      - type: emit_alert
        params: {}
""")
    assert len(list(engine.evaluate(_make_event(status="fail")))) == 1
    assert list(engine.evaluate(_make_event(status="ok"))) == []


def test_starts_with_operator(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: test
    enabled: true
    when:
      - field: data.cmd
        op: starts_with
        value: "sudo"
    actions:
      - type: emit_alert
        params: {}
""")
    assert len(list(engine.evaluate(_make_event(cmd="sudo rm -rf /")))) == 1
    assert list(engine.evaluate(_make_event(cmd="ls /tmp"))) == []


def test_in_list_operator(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: test
    enabled: true
    when:
      - field: data.tool
        op: in_list
        value: [masscan, nmap, zmap]
    actions:
      - type: emit_alert
        params: {}
""")
    assert len(list(engine.evaluate(_make_event(tool="nmap")))) == 1
    assert list(engine.evaluate(_make_event(tool="curl"))) == []


def test_not_in_subnet_operator(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: test
    enabled: true
    when:
      - field: data.src_ip
        op: not_in_subnet
        value: 10.0.0.0/8
    actions:
      - type: emit_alert
        params: {}
""")
    assert len(list(engine.evaluate(_make_event(src_ip="1.2.3.4")))) == 1
    assert list(engine.evaluate(_make_event(src_ip="10.0.0.5"))) == []


def test_range_operator(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: test
    enabled: true
    when:
      - field: data.score
        op: range
        value: [5, 10]
    actions:
      - type: emit_alert
        params: {}
""")
    assert len(list(engine.evaluate(_make_event(score=7)))) == 1
    assert list(engine.evaluate(_make_event(score=2))) == []


def test_exists_operator(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: test
    enabled: true
    when:
      - field: data.credential
        op: exists
    actions:
      - type: emit_alert
        params: {}
""")
    assert len(list(engine.evaluate(_make_event(credential="admin")))) == 1
    assert list(engine.evaluate(_make_event())) == []


def test_or_condition_group(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: or-test
    enabled: true
    when: []
    condition_groups:
      - logic: or
        conditions:
          - field: data.port
            op: equals
            value: 22
          - field: data.port
            op: equals
            value: 3389
    actions:
      - type: emit_alert
        params: {}
""")
    assert len(list(engine.evaluate(_make_event(port=22)))) == 1
    assert len(list(engine.evaluate(_make_event(port=3389)))) == 1
    assert list(engine.evaluate(_make_event(port=80))) == []


def test_invalid_operator_raises(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("""
rules:
  - name: bad
    when:
      - field: data.x
        op: made_up_operator
        value: 1
    actions:
      - type: emit_alert
        params: {}
""")
    with pytest.raises(ValueError, match="unknown operator"):
        RuleEngine.from_yaml(str(f))


def test_disabled_rule_not_evaluated(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: disabled
    enabled: false
    when:
      - field: event_type
        op: equals
        value: scan
    actions:
      - type: emit_alert
        params: {}
""")
    e = _make_event()
    e.event_type = "scan"
    assert list(engine.evaluate(e)) == []


def test_approved_by_required(tmp_path):
    f = tmp_path / "rules.yaml"
    f.write_text("""
rules:
  - name: needs-approval
    enabled: true
    when:
      - field: event_type
        op: equals
        value: scan
    actions:
      - type: emit_alert
        params: {}
""")
    engine = RuleEngine.from_yaml(str(f), required_approvers=["alice"])
    e = _make_event()
    e.event_type = "scan"
    assert list(engine.evaluate(e)) == []


def test_subnet_condition(tmp_path):
    engine = _engine(tmp_path, """
rules:
  - name: subnet-test
    enabled: true
    when:
      - field: data.src_ip
        op: in_subnet
        value: 10.10.20.0/24
    actions:
      - type: emit_alert
        params: {}
""")
    assert len(list(engine.evaluate(_make_event(src_ip="10.10.20.5")))) == 1
