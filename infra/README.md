# Infrastructure

Kubernetes manifests and Terraform modules for deploying all ADG components.

## Directory layout

```
infra/
├── k8s/
│   ├── honeypots/          # Honeypot namespace, network policy, and per-honeypot deployments
│   │   ├── namespace.yaml
│   │   ├── networkpolicy.yaml
│   │   ├── controller.yaml
│   │   ├── controller-hpa.yaml
│   │   ├── cowrie.yaml
│   │   ├── dionaea.yaml
│   │   ├── pyrdp.yaml
│   │   ├── samba.yaml
│   │   ├── fake-jenkins.yaml
│   │   └── fake-grafana.yaml
│   ├── bus/                # Kafka and Redis for the event bus
│   │   ├── kafka.yaml
│   │   ├── kafka-ha.yaml
│   │   ├── redis.yaml
│   │   └── redis-ha.yaml
│   ├── storage/            # Postgres for durable controller state
│   │   ├── postgres.yaml
│   │   └── postgres-secret.yaml
│   ├── retention/          # CronJobs for log and PCAP cleanup
│   │   ├── log-retention.yaml   (14-day audit log retention)
│   │   └── pcap-retention.yaml  (7-day PCAP retention)
│   ├── token-engine.yaml
│   ├── token-engine-hpa.yaml
│   ├── soar.yaml
│   ├── soar-hpa.yaml
│   └── token-rotation.yaml  # CronJob to rotate honeytokens on schedule
└── terraform/
    ├── aws/                 # AWS decoy IAM users, roles, and S3 buckets
    ├── azure/               # Azure AD decoy service principals
    └── gcp/                 # GCP decoy service accounts
```

## Kubernetes deployment order

```bash
# 1. Namespace and network isolation
kubectl apply -f k8s/honeypots/namespace.yaml
kubectl apply -f k8s/honeypots/networkpolicy.yaml

# 2. Event bus
kubectl apply -f k8s/bus/kafka.yaml
kubectl apply -f k8s/bus/redis.yaml

# 3. Durable state
kubectl apply -f k8s/storage/postgres-secret.yaml
kubectl apply -f k8s/storage/postgres.yaml

# 4. Core services
kubectl apply -f k8s/honeypots/controller.yaml
kubectl apply -f k8s/token-engine.yaml
kubectl apply -f k8s/soar.yaml

# 5. Honeypots
kubectl apply -f k8s/honeypots/

# 6. Autoscaling
kubectl apply -f k8s/honeypots/controller-hpa.yaml
kubectl apply -f k8s/token-engine-hpa.yaml
kubectl apply -f k8s/soar-hpa.yaml

# 7. Retention and rotation CronJobs
kubectl apply -f k8s/retention/
kubectl apply -f k8s/token-rotation.yaml
```

## Resource defaults

| Component | CPU request | CPU limit | Memory request | Memory limit |
|---|---|---|---|---|
| Controller | 100m | 500m | 128Mi | 512Mi |
| Token engine | 100m | 300m | 128Mi | 256Mi |
| SOAR playbooks | 100m | 300m | 128Mi | 256Mi |
| Cowrie/Dionaea | 50m | 200m | 64Mi | 256Mi |
| Fake apps | 50m | 100m | 64Mi | 128Mi |

## Default service ports

| Service | Port |
|---|---|
| Controller | 8080 |
| Token engine | 8081 |
| SOAR playbooks | 8090 |
| Fake Jenkins | 8080 |
| Fake Grafana | 3000 |
| Fake MySQL | 3306 |
| Fake SMTP | 25 |
| Fake S3 | 9000 |

## Network policy

The `honeypots` namespace denies all egress by default. Controller pods are the only permitted egress path — honeypots may only reach the controller webhook. This prevents real attacker tooling from establishing outbound connections if a honeypot container is compromised.

## Secrets

Never commit secrets to manifests. Supply via Kubernetes `Secret` resources or Vault:

- `ADG_JWT_SECRET` — controller, token engine, SOAR
- `ADG_SIEM_TOKEN` — Splunk/Elastic/Sentinel credentials
- `ADG_DNS_API_KEY` — PowerDNS / Route53 / Cloudflare
- `ADG_AD_PASSWORD` — Active Directory bind password
- `ADG_ABUSEIPDB_KEY`, `ADG_OTX_KEY` — threat-intel enrichment
- `ADG_SOAR_PAGERDUTY_ROUTING_KEY`, `ADG_SOAR_SLACK_WEBHOOK_URL` — SOAR notifications
- Postgres password — referenced by `postgres-secret.yaml`

## Terraform modules

Terraform modules provision cloud-side decoy resources and store their credentials in Vault for use by the token engine and breadcrumb roles:

- **`terraform/aws/`** — IAM decoy user with no real permissions, S3 decoy bucket; credentials written to Vault
- **`terraform/azure/`** — Azure AD service principal with no role assignments; client secret written to Vault
- **`terraform/gcp/`** — GCP service account with no IAM bindings; key JSON written to Vault

## HA notes

For active/active controller deployments:
- Set `ADG_LEADER_ELECTION=true` and point all replicas at the same Redis
- Use `ADG_BUS_MODE=redis` for durable cross-replica event delivery
- Set `ADG_STATE_DB_URL` to a shared Postgres connection string
- Use `kafka-ha.yaml` and `redis-ha.yaml` for bus resilience
