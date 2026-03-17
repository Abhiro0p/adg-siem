from datetime import datetime, timezone

from app.models import Event
from app.rules import RuleEngine


def test_subnet_condition(tmp_path):
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        """
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
        """
    )
    engine = RuleEngine.from_yaml(str(rules_yaml))
    event = Event(
        source="suricata",
        event_type="conn",
        ts=datetime.now(timezone.utc),
        data={"src_ip": "10.10.20.5"},
    )
    matches = list(engine.evaluate(event))
    assert len(matches) == 1
