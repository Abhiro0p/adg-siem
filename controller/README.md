# Controller

Adaptive deception controller — the central decision engine of ADG. Consumes events from the bus, evaluates YAML rules, enriches and scores interactions, maps to MITRE ATT&CK, and orchestrates lure deployment, DNS updates, AD account lifecycle, and SIEM/SOAR alert delivery.

## Endpoints

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/health/live` | public | Liveness probe |
| GET | `/health/ready` | public | Readiness probe (Postgres, Redis, Vault, SIEM) |
| POST | `/events` | `controller:write` | Ingest deception events |
| GET | `/lures` | `controller:read` | List active lure deployments |
| GET | `/rules` | `controller:read` | List rules (governance review) |
| POST | `/rules/reload` | `controller:admin` | Reload rules after approval |
| POST | `/realism` | `controller:read` | Score realism of an event |
| POST | `/coverage` | `controller:read` | Coverage heatmap (by subnet, event type, source) |
| POST | `/enrich/ip` | `controller:read` | Manual IP enrichment (GeoIP, AbuseIPDB, OTX, rDNS) |
| GET | `/techniques/{technique_id}` | `controller:read` | MITRE technique detail |
| GET | `/cmdb/assets` | `controller:read` | Pull CMDB asset inventory |
| POST | `/ad/decoy` | `controller:admin` | Create AD decoy account |
| POST | `/ad/disable` | `controller:admin` | Disable AD decoy account |
| POST | `/ad/group` | `controller:admin` | Manage AD group membership |
| POST | `/auth/revoke` | `controller:admin` | Revoke a JWT by JTI |
| GET | `/metrics` | public | Prometheus metrics |

## Key modules

| Module | Responsibility |
|---|---|
| `app/rules.py` | YAML rule engine — 20 operators, AND/OR condition groups, stateful sliding-window threshold |
| `app/kill_chain.py` | 100+ MITRE ATT&CK technique mappings (tactic, kill-chain phase, description, URL) |
| `app/enrichment.py` | Parallel IP enrichment: GeoIP, reverse DNS, AbuseIPDB, AlienVault OTX |
| `app/deception.py` | Multi-factor realism scoring, coverage mapping, z-score baseline anomaly detection |
| `app/siem.py` | Multi-SIEM fan-out: webhook (HMAC-SHA256), Splunk, Elasticsearch, Sentinel, Sumo Logic, Datadog |
| `app/bus.py` | In-memory bus (backpressure, graceful drain) and Redis Streams consumer group (ACK, pending replay) |
| `app/dns_providers.py` | DNS updates: PowerDNS, RFC2136, Route53, Cloudflare — with input allowlist sanitisation |
| `app/ad.py` | AD decoy account create/enable/disable, group membership, OU placement |
| `app/auth.py` | JWT validation (`sub`, `exp`, `iat`, `jti` required), token blacklist with TTL purge |
| `app/redaction.py` | Sensitive field masking: 30+ field names + value-pattern regexes (AWS keys, PEM, PATs, JWTs) |
| `app/audit.py` | Action-level audit logging, `request_id` correlation via `AuditMiddleware` |
| `app/health.py` | Readiness checks: Postgres, Redis, Vault, downstream SIEM |
| `app/alerts.py` | Alert construction with enrichment, kill-chain, MITRE technique details |
| `app/state.py` | SQLite/Postgres state store for lure deployments |

## Rule format

```yaml
- name: port-scan-detected
  enabled: true
  approved_by: [alice, bob]
  severity: high
  tags: [reconnaissance, T1595]
  when:
    - field: event_type
      operator: equals
      value: port_scan
  condition_groups:
    - logic: or
      conditions:
        - field: dst_port
          operator: in_list
          value: [22, 3389, 445, 3306]
        - field: dst_port
          operator: range
          value: [8080, 8099]
  actions:
    - type: deploy_lure
      params: {lure_type: ssh_honeypot}
    - type: alert
      params: {severity: high}
```

### Supported operators
`equals`, `not_equals`, `contains`, `not_contains`, `starts_with`, `ends_with`, `regex`, `in_list`, `not_in_list`, `in_subnet`, `not_in_subnet`, `gt`, `lt`, `gte`, `lte`, `range`, `exists`, `not_exists`, `is_empty`, `threshold`

The `threshold` operator requires `value: {key_field: "src_ip", count: 5, window_seconds: 60}` and uses a thread-safe in-process sliding window.

## Running locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
```

## Tests

```bash
python -m pytest tests/ -v
```

39 tests covering: rule operators, threshold detection, OR/AND groups, deception scoring, coverage, baseline tracker, MITRE mapping, redaction, and state store.

## Environment variables

See [docs/configuration.md](../docs/configuration.md) for the full list. Key variables:

| Variable | Default | Purpose |
|---|---|---|
| `ADG_JWT_SECRET` | — | JWT signing secret (required) |
| `ADG_BUS_MODE` | `in-memory` | `in-memory` or `redis` |
| `ADG_REDIS_URL` | `redis://localhost:6379/0` | Redis URL |
| `ADG_SIEM_MODE` | `webhook` | Comma-separated emitters: `webhook,splunk,elastic,sentinel,sumologic,datadog` |
| `ADG_STATE_DB_URL` | SQLite path | Postgres URL for HA |
| `ADG_ENRICHMENT_ENABLED` | `true` | Enable IP threat-intel enrichment |
| `ADG_ABUSEIPDB_KEY` | — | AbuseIPDB API key |
| `ADG_OTX_KEY` | — | AlienVault OTX API key |
| `ADG_VAULT_ADDR` | — | HashiCorp Vault address |
