# Infrastructure Manifest Values Reference

Defaults used in the Kubernetes manifests under `infra/k8s/`. Override via Helm values or `kubectl set env` when deploying to different environments.

## Namespace and network policy

- **Namespace**: `honeypots` (`infra/k8s/honeypots/namespace.yaml`)
- **Network policy** (`infra/k8s/honeypots/networkpolicy.yaml`): default-deny egress for the `honeypots` namespace; only egress to the controller webhook service is permitted

## Controller

File: `infra/k8s/honeypots/controller.yaml`

| Setting | Value |
|---|---|
| Image | `adg/controller:latest` |
| Container port | 8080 |
| Liveness probe | `GET /health/live` |
| Readiness probe | `GET /health/ready` |
| CPU request/limit | `100m` / `500m` |
| Memory request/limit | `128Mi` / `512Mi` |
| `ADG_RULES_PATH` | `/app/rules/example.yaml` |
| `ADG_BUS_MODE` | `in-memory` (override to `redis` for HA) |
| `ADG_ORCHESTRATION_MODE` | `dry-run` (override to `kubernetes` for live deployment) |

HPA (`infra/k8s/honeypots/controller-hpa.yaml`): CPU-based, `minReplicas: 1`, `maxReplicas: 5`, `averageUtilization: 60`. Requires Postgres state store and Redis bus for multi-replica operation.

## Token engine

File: `infra/k8s/token-engine.yaml`

| Setting | Value |
|---|---|
| Image | `adg/token-engine:latest` |
| Container port | 8081 |
| Liveness/readiness probe | `GET /health` |
| CPU request/limit | `100m` / `300m` |
| Memory request/limit | `128Mi` / `256Mi` |

HPA (`infra/k8s/token-engine-hpa.yaml`): CPU-based, `minReplicas: 1`, `maxReplicas: 10`.

## SOAR playbooks

File: `infra/k8s/soar.yaml`

| Setting | Value |
|---|---|
| Image | `adg/soar-playbooks:latest` |
| Container port | 8090 |
| Liveness/readiness probe | `GET /health` |
| CPU request/limit | `100m` / `300m` |
| Memory request/limit | `128Mi` / `256Mi` |

HPA (`infra/k8s/soar-hpa.yaml`): CPU-based, `minReplicas: 1`, `maxReplicas: 5`.

## Honeypots

Each honeypot manifest (`infra/k8s/honeypots/*.yaml`) includes three containers:
1. **Honeypot** — the service container
2. **pcap** — `nicolaka/netshoot` running `tcpdump` writing to `/pcap` (`emptyDir`)
3. **pcap-forwarder** — forwards PCAP files to Kafka

| Honeypot | Image | Service port |
|---|---|---|
| Cowrie | `cowrie/cowrie:latest` | 22, 23 |
| Dionaea | `dinotools/dionaea:latest` | 21, 80, 443, 445, 1433 |
| PyRDP | `gosecure/pyrdp:latest` | 3389 |
| Fake Jenkins | `adg/fake-jenkins:latest` | 8080 |
| Fake Grafana | `adg/fake-grafana:latest` | 3000 |
| Samba | `dperson/samba:latest` | 445 |

PCAP forwarder env vars:
- `KAFKA_BROKER`: `kafka:9092`
- `KAFKA_TOPIC`: `pcap-events`

## Event bus

### Kafka (`infra/k8s/bus/kafka.yaml`)

| Setting | Value |
|---|---|
| Image | `bitnami/kafka:3.7` |
| Listeners | `PLAINTEXT://:9092` (replace with TLS in production) |
| Log retention | 168h (7 days) |

Use `kafka-ha.yaml` for a 3-broker StatefulSet in production.

### Redis (`infra/k8s/bus/redis.yaml`)

| Setting | Value |
|---|---|
| Image | `redis:7.2` |
| Port | 6379 |
| Persistence | `appendonly yes` in ConfigMap |

Use `redis-ha.yaml` (Redis Sentinel) for HA.

## Postgres (controller state)

File: `infra/k8s/storage/postgres.yaml`

| Setting | Value |
|---|---|
| Image | `postgres:16` |
| Port | 5432 |
| Database | `adg` |
| PVC size | `10Gi` |
| Password | from `postgres-secret.yaml` (replace placeholder before applying) |

## Retention CronJobs

| CronJob | Schedule | Action |
|---|---|---|
| `log-retention` | `0 2 * * *` (daily 02:00) | Delete audit logs older than 14 days |
| `pcap-retention` | `0 3 * * *` (daily 03:00) | Delete PCAPs older than 7 days |
| `token-rotation` | `0 0 1 * *` (monthly) | POST to token engine `/rotate` for all token types |

## Secrets

Never store these in manifests. Supply via Kubernetes `Secret` or Vault:

| Secret | Services |
|---|---|
| `ADG_JWT_SECRET` | controller, token-engine, soar |
| `ADG_SIEM_TOKEN` | controller |
| `ADG_SIEM_WEBHOOK_SECRET` | controller |
| `ADG_SIEM_SENTINEL_SHARED_KEY` | controller |
| `ADG_DNS_API_KEY` | controller |
| `ADG_ABUSEIPDB_KEY` | controller |
| `ADG_OTX_KEY` | controller |
| `ADG_AD_PASSWORD` | controller, soar |
| `ADG_SOAR_SLACK_WEBHOOK_URL` | soar |
| `ADG_SOAR_PAGERDUTY_ROUTING_KEY` | soar |
| `ADG_SOAR_JIRA_TOKEN` | soar |
| `ADG_SOAR_SENTINELONE_TOKEN` | soar |
| Postgres password | postgres-secret.yaml |

## Kafka TLS (production)

Replace PLAINTEXT listeners with TLS before production deployment:

```yaml
env:
  - name: KAFKA_LISTENERS
    value: "SSL://:9093"
  - name: KAFKA_SSL_KEYSTORE_LOCATION
    value: "/opt/bitnami/kafka/config/certs/kafka.keystore.jks"
  # ... additional TLS config
```

Update `KAFKA_BROKER` env on the PCAP forwarder to use port 9093 with SSL protocol.
