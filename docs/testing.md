# Testing

## Unit tests

### Controller (39 tests — all passing)

```bash
cd controller
pip install -r requirements.txt
python -m pytest tests/ -v
```

| Test file | Coverage |
|---|---|
| `test_rules.py` | 14 tests: all 20 operators, OR/AND condition groups, threshold detection, disabled rules, approval requirement, subnet conditions |
| `test_redaction.py` | 7 tests: field-name redaction, nested dicts, AWS key value detection, JWT value detection, list values, `extra_fields` param, non-sensitive unchanged |
| `test_deception.py` | 7 tests: realism score structure, high-value port boost, label classification, scanner UA boost, coverage by subnet, coverage by event type, baseline tracker |
| `test_kill_chain.py` | 10 tests: deduplication and ordering, unknown techniques, `tactic_for`, `describe_technique`, `enrich_techniques` with URL, tactic fallback, brute-force mapping, lateral movement, exfiltration |
| `test_state.py` | 1 test: SQLite state store create/read/update |
| `test_actions.py` | 1 test: subnet condition integration |

### Token engine

```bash
cd token-engine
python -m pytest tests/ -v
```

Tests cover: token generation for all 15 types, format validation, access event logging, bundle generation.

### SOAR playbooks

```bash
cd soar-playbooks
python -m pytest tests/ -v
```

Tests cover: playbook loading, trigger matching, action dispatch, audit log output.

## Integration tests

Test the full event pipeline with a local bus:

```bash
# Start controller with in-memory bus
ADG_BUS_MODE=in-memory uvicorn app.main:app --port 8080 &

# Ingest an event and verify alert delivery
curl -X POST http://localhost:8080/events \
  -H "Authorization: Bearer $JWT" \
  -d '{
    "event_type": "port_scan",
    "src_ip": "10.0.1.50",
    "dst_port": 22,
    "protocol": "tcp",
    "timestamp": "2025-01-01T00:00:00Z"
  }'

# Verify lures and coverage
curl http://localhost:8080/lures -H "Authorization: Bearer $JWT"
curl http://localhost:8080/coverage -H "Authorization: Bearer $JWT"
```

## Performance tests

```bash
# Load test against events endpoint
python validation/scripts/load_test.py --url http://localhost:8080/events \
  --rate 100 --duration 60 --jwt $JWT
```

Target: < 50 ms p95 latency at 100 events/second with in-memory bus. Redis bus adds ~5 ms per event.

## Simulated attacks (Atomic Red Team)

```bash
# Port scan simulation
python validation/scripts/simulate_port_scan.py --target http://localhost:8080

# Brute force simulation (T1110)
# Point against Cowrie SSH or Fake SMTP endpoints
```

See `validation/atomic-red-team.md` for the full test plan with specific ATT&CK technique IDs.

## CALDERA integration

Deploy a CALDERA server in a lab subnet and run discovery operations against honeypot service IPs. Expected detections:

- T1046 Network Service Scanning → `port_scan` events → rule fires → lure deployed
- T1110 Brute Force → auth events from Cowrie/fake-SMTP → threshold rule fires → SOAR page
- T1021 Remote Services → RDP events from PyRDP → alert with lateral-movement kill-chain

See `validation/caldera.md` for the step-by-step CALDERA configuration.

## Chaos testing

```bash
# Restart Redis and confirm controller resumes processing
kubectl rollout restart deployment/redis -n honeypots
# Controller should reconnect within 2s and replay pending messages from consumer group

# Restart controller mid-stream
kubectl rollout restart deployment/adg-controller -n honeypots
# Pending unACKed Redis Stream messages should be replayed on startup
# No events should be lost
```

## Evidence collection checklist

After a test run, collect:

- [ ] `/lures` output (controller deployed lures)
- [ ] SIEM alerts with MITRE technique and kill-chain phase
- [ ] `state/*.log` SOAR action artifacts
- [ ] PCAP files in Kafka `pcap-events` topic
- [ ] Audit logs with `request_id` correlation
- [ ] Prometheus metric snapshots (throughput, latency, error rate)
