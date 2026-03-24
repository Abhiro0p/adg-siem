# Validation Plan

ADG uses two adversary simulation frameworks for end-to-end validation: Atomic Red Team for quick technique-level tests and MITRE CALDERA for full multi-step operation simulations.

## What to validate

| Layer | Validation goal |
|---|---|
| Breadcrumbs | Credentials accessed → token engine `/access` event fires → alert reaches SIEM |
| Honeypots | Connection attempt → JSON event emitted → rule matches → lure deployed |
| Controller rules | Specific ATT&CK techniques trigger correct rules with correct severity and tags |
| MITRE mapping | Alerts include correct tactic, kill-chain phase, and technique URL |
| Enrichment | Alerts include GeoIP, AbuseIPDB score, OTX pulse count for external IPs |
| SOAR | Alert received → correct playbook triggers → actions execute (Slack, PD, Jira, etc.) |
| PCAP | Every honeypot connection captured → forwarded to Kafka with SHA-256 hash |

## ATT&CK techniques to exercise

| Technique | ID | Honeypot/vector |
|---|---|---|
| Network Service Scanning | T1046 | Port sweep against honeypots |
| Brute Force — Password Spraying | T1110.003 | Auth attempts on fake-SMTP, fake-MySQL, Cowrie |
| Remote Services — SSH | T1021.004 | Cowrie |
| Remote Services — RDP | T1021.001 | PyRDP |
| SMB/Windows Admin Shares | T1021.002 | Dionaea, Samba |
| Valid Accounts — Cloud | T1078.004 | AWS key breadcrumb access |
| Steal Application Access Token | T1528 | Token engine access events |
| Exploit Public-Facing Application | T1190 | Fake Jenkins / Grafana |
| Command and Scripting Interpreter | T1059 | Cowrie shell interaction |
| Data from Cloud Storage | T1530 | Fake S3 bucket enumeration |

## Evidence to collect after each run

- [ ] Controller `/lures` response (lures deployed for matched rules)
- [ ] SIEM alerts with MITRE technique ID, tactic, and kill-chain phase
- [ ] SOAR `state/*.log` and action audit log entries
- [ ] PCAP files present in Kafka `pcap-events` topic with valid SHA-256 hash
- [ ] Controller `/coverage` response (heatmap updated)
- [ ] Prometheus metric delta for `adg_alerts_emitted_total` and `adg_rules_evaluated_total`

## Quick smoke test

```bash
# Simulate a port scan event
python validation/scripts/simulate_port_scan.py \
  --url http://controller:8080/events \
  --jwt $JWT \
  --src-ip 203.0.113.50 \
  --ports 22,3306,3389,445,8080

# Expected: rule fires, lure deployed, alert in SIEM with T1046 mapping

# Load test
python validation/scripts/load_test.py \
  --url http://controller:8080/events \
  --jwt $JWT \
  --rate 100 \
  --duration 60
```

## Pass/fail criteria

| Check | Pass |
|---|---|
| Port scan rule fires | Alert received in SIEM within 5 s |
| Brute force threshold | Rule fires after N auth events in window |
| MITRE mapping | Alert includes `kill_chain` list and `techniques` array |
| Enrichment | Alert includes `enrichment.geoip.country` for external IPs |
| Realism score | Alert includes `realism.score` between 0 and 1 |
| SOAR action | Slack message received within 30 s of alert |
| PCAP | File appears in Kafka with matching SHA-256 |
| No data loss | All events ACKed; no pending messages after 60 s |
