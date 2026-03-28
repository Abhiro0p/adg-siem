# Operations

## Day-to-day tasks

### Token rotation

Honeytokens should be rotated regularly. The `token-rotation` CronJob does this automatically, but you can trigger it manually:

```bash
curl -X POST http://token-engine:8081/rotate \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -d '{"token_type": "aws_access_key"}'
```

Rotation revokes the existing token and generates a new one. The old token ID is preserved in the store with `status=rotated` for audit purposes. After rotation, re-run the breadcrumb Ansible playbook to push updated values to endpoints.

### Rule management

Rules live in `ADG_RULES_PATH` (default: `./rules/example.yaml`). To update rules:

1. Edit the YAML file (or merge via GitOps)
2. Call `/rules/reload` with an admin JWT:

```bash
curl -X POST http://controller:8080/rules/reload \
  -H "Authorization: Bearer $ADMIN_JWT"
```

Rules with `approved_by` set require at least one matching approver identity in the JWT `sub` field. Review pending rules at `/rules` before reloading.

### Checking coverage

```bash
curl http://controller:8080/coverage -H "Authorization: Bearer $JWT"
```

Returns breakdown by subnet, event type, and source IP. Use this to identify gaps in deception coverage.

### Enriching an IP manually

```bash
curl "http://controller:8080/enrich/ip?ip=203.0.113.50" \
  -H "Authorization: Bearer $JWT"
```

Returns GeoIP, reverse DNS, AbuseIPDB confidence score, and OTX pulse count.

## Monitoring

### Health endpoints

| Endpoint | Checks |
|---|---|
| `/health/live` | Process alive (always 200 if up) |
| `/health/ready` | Postgres connectivity, Redis ping, Vault reachability, downstream SIEM |

Wire both into your Kubernetes liveness and readiness probes respectively.

### Prometheus metrics

All services expose `/metrics` in Prometheus format. Key metrics to alert on:

- `http_requests_total{status="5xx"}` — server errors
- `http_request_duration_seconds` — latency percentiles
- `adg_bus_queue_depth` — in-memory bus backlog (alert if sustained > 80% of `ADG_BUS_QUEUE_SIZE`)
- `adg_rules_evaluated_total` — rule evaluation throughput
- `adg_alerts_emitted_total` — alert delivery count per SIEM emitter

### Audit logs

Each service writes structured JSON audit logs to `ADG_*_AUDIT_LOG_PATH`. Ship them to your SIEM with Filebeat or Fluentd. Every log entry includes:

- `request_id` — correlates across service boundaries
- `action` — the specific operation performed
- `subject` — the JWT `sub` of the caller
- `resource` — the affected resource
- `outcome` — `success` or `failure`
- `timestamp`

### Bus backlog (Redis Streams)

```bash
redis-cli XLEN adg-events                    # total events in stream
redis-cli XPENDING adg-events adg-controller - + 10  # pending unACKed messages
```

Alert if pending count exceeds 1000 for more than 5 minutes — this indicates the controller is falling behind.

## Scaling

### Horizontal scaling

Controller: requires `ADG_BUS_MODE=redis`, `ADG_LEADER_ELECTION=true`, and a shared `ADG_STATE_DB_URL` (Postgres). In-memory bus and SQLite state do not support multiple replicas.

Token engine and SOAR playbooks are stateless and scale horizontally without additional configuration.

HPA targets are in `infra/k8s/*-hpa.yaml`. Tune `minReplicas`, `maxReplicas`, and `averageUtilization` for your load profile.

### Increasing bus capacity

```bash
# Redis Streams: no hard limit; monitor XLEN and consumer group lag
# In-memory: increase ADG_BUS_QUEUE_SIZE (requires restart)
```

## Retention

| Data | Default retention | Config |
|---|---|---|
| Audit logs | 14 days | `infra/k8s/retention/log-retention.yaml` |
| PCAPs | 7 days | `infra/k8s/retention/pcap-retention.yaml` |
| Token access events | Indefinite (SQLite) | Manual purge or archive |
| Redis Streams | Configured `MAXLEN` | Set on stream or via CronJob |

## Credential rotation schedule

| Credential | Recommended rotation |
|---|---|
| JWT signing secrets | 90 days |
| Honeytoken values | 30 days (automated via CronJob) |
| SIEM API tokens | 90 days |
| DNS API keys | 90 days |
| AD bind password | 90 days |
| AbuseIPDB / OTX keys | 180 days |
| SentinelOne / CrowdStrike tokens | Per vendor policy |

## Admin UI

The controller serves a lightweight admin page at `/` when `ADG_ADMIN_UI_ENABLED=true`. Disable it in production environments where the controller is not exposed to analyst browsers:

```bash
ADG_ADMIN_UI_ENABLED=false
```

## Breadcrumb refresh

After token rotation, push updated credentials to all endpoints:

```bash
ansible-playbook -i inventory/hosts breadcrumbs/ansible/playbooks/deploy-linux.yaml \
  --extra-vars "@breadcrumbs/vars/latest-tokens.yaml"
```

Use `rollback-linux.yaml` to remove all breadcrumbs from an endpoint cleanly if it is being decommissioned or re-imaged.
