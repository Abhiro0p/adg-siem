# Architecture

## Overview

ADG is a layered deception platform composed of five independently deployable services that communicate through a shared event bus. Each layer has a single responsibility; no layer has direct access to another's state store.

```
Endpoints / Cloud          →  Breadcrumbs & Tokens
Honeypots / Emulators      →  Event emission
Event Bus (Redis Streams)  →  Durable delivery
Controller                 →  Rules, enrichment, orchestration
SIEM / SOAR               →  Alerting & response
```

## Component diagram

```mermaid
flowchart LR
  subgraph Endpoints
    Win[Windows Hosts]
    Lin[Linux Hosts]
  end

  subgraph Tokens["Token Engine :8081"]
    TE[15 token types]
    Bundle[Decoy file bundle]
  end

  subgraph Honeypots["Honeypot Farm"]
    Cowrie[Cowrie SSH/Telnet]
    Dionaea[Dionaea SMB/HTTP]
    PyRDP[PyRDP RDP]
    Jenkins[Fake Jenkins :8080]
    Grafana[Fake Grafana :3000]
    MySQL[Fake MySQL :3306]
    SMTP[Fake SMTP :25]
    S3[Fake S3 :9000]
    PCAP[PCAP Forwarder→Kafka]
  end

  subgraph Bus["Event Bus"]
    Redis[Redis Streams\nconsumer groups]
    Kafka[Kafka\nPCAP topic]
  end

  subgraph Controller["Controller :8080"]
    Rules[Rule Engine\n20 operators + threshold]
    Enrich[IP Enrichment\nGeoIP·AbuseIPDB·OTX·rDNS]
    MITRE[MITRE ATT&CK\n100+ techniques]
    Score[Realism Scorer\n+ Baseline Anomaly]
    DNS[DNS Providers\nPowerDNS·RFC2136·Route53·CF]
    AD[AD Lifecycle\ncreate·enable·disable·group]
    Orch[Orchestrator\nKubernetes / dry-run]
    Audit[Audit Logger\nrequest_id correlation]
  end

  subgraph SIEM["SIEM Fan-out"]
    Webhook[Webhook HMAC-SHA256]
    Splunk[Splunk HEC]
    Elastic[Elasticsearch]
    Sentinel[MS Sentinel SharedKey]
    Sumo[Sumo Logic]
    Datadog[Datadog]
  end

  subgraph SOAR["SOAR Playbooks :8090"]
    Slack[Slack notify]
    PD[PagerDuty page]
    Jira[Jira ticket]
    ADdis[AD disable]
    S1[SentinelOne isolate]
    FW[Firewall block]
    Snap[Snapshot + SHA-256]
    IOC[IOC extraction]
  end

  Win -->|Ansible breadcrumbs| TE
  Lin -->|Ansible breadcrumbs| TE
  Cowrie --> Redis
  Dionaea --> Redis
  PyRDP --> Redis
  Jenkins --> Redis
  Grafana --> Redis
  MySQL --> Redis
  SMTP --> Redis
  S3 --> Redis
  Honeypots --> PCAP --> Kafka

  TE --> Redis
  Redis --> Rules
  Rules --> Enrich
  Rules --> MITRE
  Rules --> Score
  Rules --> Orch
  Orch --> DNS
  Orch --> AD
  Rules --> Webhook & Splunk & Elastic & Sentinel & Sumo & Datadog
  Webhook --> SOAR
  SOAR --> Slack & PD & Jira & ADdis & S1 & FW & Snap & IOC
```

## Trust boundaries

| Boundary | Enforcement |
|---|---|
| Honeypot → Controller | Egress deny network policy; only controller webhook permitted |
| External → Controller | mTLS via ingress (`X-SSL-Client-Verify: SUCCESS`) + JWT RBAC |
| Controller → AD | Dedicated bind user with minimum required LDAP permissions |
| Controller → DNS | Input allowlist sanitisation before any DNS write |
| Controller → SIEM | HMAC-SHA256 webhook signature; TLS to all SIEM endpoints |
| Secrets | Vault or Kubernetes Secrets; never in manifests or code |

## State and availability

| Data | Store | HA option |
|---|---|---|
| Lure deployments, rule state | SQLite (default) | Postgres (`ADG_STATE_DB_URL`) |
| Event bus | In-memory (default) | Redis Streams consumer group (`ADG_BUS_MODE=redis`) |
| Leader election | Redis (`ADG_LEADER_ELECTION=true`) | Shared Redis across replicas |
| Token store | SQLite | Postgres |
| Audit logs | Local file | Ship to SIEM via Filebeat |

## Observability stack

- **Metrics**: Prometheus FastAPI Instrumentator → `/metrics` on each service
- **Tracing**: OpenTelemetry SDK → OTLP exporter → Jaeger or Tempo
- **Logs**: python-json-logger structured JSON → Filebeat → Elasticsearch/Splunk
- **Audit**: Action-level audit log per service with `request_id` correlation
- **Health**: `/health/live` (liveness) and `/health/ready` (checks Postgres, Redis, Vault, SIEM)

## Data storage

| Data type | Path |
|---|---|
| Controller state | `ADG_STATE_DB_URL` (SQLite or Postgres) |
| Audit logs | `ADG_*_AUDIT_LOG_PATH` |
| PCAP ring buffer | `/pcap` emptyDir → Kafka `pcap-events` topic |
| Rule definitions | `ADG_RULES_PATH` (YAML, GitOps) |
| Playbooks | `soar-playbooks/playbooks/*.yaml` |
| Token store | `ADG_TOKEN_DB_PATH` (SQLite) |
