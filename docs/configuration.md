# Configuration Reference

All services use environment variables with service-specific prefixes. Secrets should be supplied via HashiCorp Vault or Kubernetes Secrets — never set in plain Kubernetes manifests.

---

## Controller (`ADG_` prefix)

### Core

| Variable | Default | Purpose |
|---|---|---|
| `ADG_RULES_PATH` | `./rules/example.yaml` | Path to deception rules YAML |
| `ADG_STATE_DB_PATH` | `./state/controller.db` | SQLite state path |
| `ADG_STATE_DB_URL` | SQLite path | Postgres URL for HA state |
| `ADG_ORCHESTRATION_MODE` | `dry-run` | `dry-run` or `kubernetes` |
| `ADG_ADMIN_UI_ENABLED` | `true` | Serve lightweight admin page |
| `ADG_TTL_REAP_INTERVAL` | `30` | Lure TTL reaper interval (s) |

### Auth & security

| Variable | Default | Purpose |
|---|---|---|
| `ADG_JWT_SECRET` | — | JWT signing secret (required) |
| `ADG_JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `ADG_MTLS_REQUIRED` | `true` | Enforce `X-SSL-Client-Verify: SUCCESS` |
| `ADG_RATE_LIMIT` | `60/minute` | slowapi rate limit string |

### Event bus

| Variable | Default | Purpose |
|---|---|---|
| `ADG_BUS_MODE` | `in-memory` | `in-memory` or `redis` |
| `ADG_REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `ADG_BUS_QUEUE_SIZE` | `1000` | In-memory bus max queue depth |
| `ADG_LEADER_ELECTION` | `false` | Enable Redis leader election |
| `ADG_LEADER_LOCK_KEY` | `adg-controller-leader` | Redis lock key |
| `ADG_LEADER_LOCK_TTL` | `20` | Leader lock TTL (s) |

### SIEM emitters

| Variable | Default | Purpose |
|---|---|---|
| `ADG_SIEM_MODE` | `webhook` | Comma-separated: `webhook,splunk,elastic,sentinel,sumologic,datadog` |
| `ADG_SIEM_URL` | `http://siem-webhook.local/ingest` | Primary SIEM URL |
| `ADG_SIEM_TOKEN` | — | SIEM auth token (Splunk/Elastic) |
| `ADG_SIEM_INDEX` | `main` | SIEM index name |
| `ADG_ALERT_WEBHOOK_URL` | — | Webhook URL (alias for `ADG_SIEM_URL`) |
| `ADG_SIEM_WEBHOOK_SECRET` | — | HMAC-SHA256 webhook signing secret |
| `ADG_SIEM_SENTINEL_WORKSPACE_ID` | — | Microsoft Sentinel workspace ID |
| `ADG_SIEM_SENTINEL_SHARED_KEY` | — | Sentinel SharedKey |
| `ADG_SIEM_SUMOLOGIC_URL` | — | Sumo Logic HTTP source URL |
| `ADG_SIEM_DATADOG_API_KEY` | — | Datadog API key |
| `ADG_SIEM_DATADOG_SITE` | `datadoghq.com` | Datadog site domain |

### DNS providers

| Variable | Default | Purpose |
|---|---|---|
| `ADG_DNS_MODE` | `powerdns` | `powerdns`, `rfc2136`, `route53`, or `cloudflare` |
| `ADG_DNS_API_URL` | `http://powerdns-api.local:8081` | PowerDNS API base URL |
| `ADG_DNS_API_KEY` | — | PowerDNS API key |
| `ADG_DNS_RFC2136_SERVER` | — | RFC2136 DNS server |
| `ADG_DNS_RFC2136_KEY_NAME` | — | RFC2136 TSIG key name |
| `ADG_DNS_RFC2136_KEY_SECRET` | — | RFC2136 TSIG secret |
| `ADG_DNS_ROUTE53_ZONE_ID` | — | AWS Route53 hosted zone ID |
| `ADG_DNS_CLOUDFLARE_ZONE_ID` | — | Cloudflare zone ID |
| `ADG_DNS_CLOUDFLARE_TOKEN` | — | Cloudflare API token |

### Active Directory

| Variable | Default | Purpose |
|---|---|---|
| `ADG_AD_SERVER` | — | LDAP server hostname |
| `ADG_AD_USER` | — | Bind user DN |
| `ADG_AD_PASSWORD` | — | Bind password |
| `ADG_AD_BASE_DN` | — | Base DN for all operations |

### Enrichment

| Variable | Default | Purpose |
|---|---|---|
| `ADG_ENRICHMENT_ENABLED` | `true` | Enable IP threat-intel enrichment |
| `ADG_ABUSEIPDB_KEY` | — | AbuseIPDB v2 API key |
| `ADG_OTX_KEY` | — | AlienVault OTX API key |

### CMDB

| Variable | Default | Purpose |
|---|---|---|
| `ADG_CMDB_URL` | — | CMDB REST API base URL |
| `ADG_CMDB_TOKEN` | — | CMDB API token |

### Governance

| Variable | Default | Purpose |
|---|---|---|
| `ADG_APPROVERS` | — | Comma-separated approver identities |
| `ADG_POLICY_PATH` | `./policies/deception-policy.yaml` | Subnet deception policy YAML |

### Observability

| Variable | Default | Purpose |
|---|---|---|
| `ADG_AUDIT_LOG_PATH` | `./state/audit.log` | Main audit log |
| `ADG_ACTION_AUDIT_LOG_PATH` | `./state/action_audit.log` | Per-action audit log |
| `ADG_OTLP_ENDPOINT` | `http://otel-collector:4317` | OpenTelemetry OTLP endpoint |

### Vault

| Variable | Default | Purpose |
|---|---|---|
| `ADG_VAULT_ADDR` | — | Vault address (e.g. `https://vault:8200`) |
| `ADG_VAULT_TOKEN` | — | Vault token |
| `ADG_VAULT_SECRET_PATH` | — | Vault KV path (e.g. `secret/data/adg/controller`) |

Vault keys read by the controller: `jwt_secret`, `dns_api_key`, `alert_webhook_url`, `siem_url`, `siem_token`, `siem_webhook_secret`, `siem_sentinel_workspace_id`, `siem_sentinel_shared_key`, `siem_sumologic_url`, `siem_datadog_api_key`, `abuseipdb_key`, `otx_key`, `ad_password`, `cmdb_token`.

### Controller endpoints

| Method | Path | Role |
|---|---|---|
| GET | `/health/live` | public |
| GET | `/health/ready` | public |
| POST | `/events` | `controller:write` |
| GET | `/lures` | `controller:read` |
| GET | `/rules` | `controller:read` |
| POST | `/rules/reload` | `controller:admin` |
| POST | `/realism` | `controller:read` |
| POST | `/coverage` | `controller:read` |
| POST | `/enrich/ip` | `controller:read` |
| GET | `/techniques/{technique_id}` | `controller:read` |
| GET | `/cmdb/assets` | `controller:read` |
| POST | `/ad/decoy` | `controller:admin` |
| POST | `/ad/disable` | `controller:admin` |
| POST | `/ad/group` | `controller:admin` |
| POST | `/auth/revoke` | `controller:admin` |

---

## Token Engine (`ADG_TOKEN_` prefix)

| Variable | Default | Purpose |
|---|---|---|
| `ADG_TOKEN_JWT_SECRET` | — | JWT signing secret (required) |
| `ADG_TOKEN_JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `ADG_TOKEN_MTLS_REQUIRED` | `true` | Enforce mTLS header |
| `ADG_TOKEN_DB_PATH` | `./state/tokens.db` | SQLite token store |
| `ADG_TOKEN_WEBHOOK_URL` | — | Access event webhook URL |
| `ADG_TOKEN_RATE_LIMIT` | `60/minute` | Rate limit |
| `ADG_TOKEN_AUDIT_LOG_PATH` | `./state/audit.log` | Audit log path |
| `ADG_TOKEN_OTLP_ENDPOINT` | `http://otel-collector:4317` | OTel endpoint |
| `ADG_TOKEN_VAULT_ADDR` | — | Vault address |
| `ADG_TOKEN_VAULT_TOKEN` | — | Vault token |
| `ADG_TOKEN_VAULT_SECRET_PATH` | — | Vault secret path |

Vault keys: `jwt_secret`, `webhook_url`.

### Token Engine endpoints

| Method | Path | Role |
|---|---|---|
| GET | `/health` | public |
| POST | `/tokens` | `token:write` |
| GET | `/tokens` | `token:read` |
| POST | `/access/{token_id}` | `token:write` |
| POST | `/rotate` | `token:admin` |
| GET | `/bundle` | `token:read` |

---

## SOAR Playbooks (`ADG_SOAR_` prefix)

| Variable | Default | Purpose |
|---|---|---|
| `ADG_SOAR_JWT_SECRET` | — | JWT signing secret (required) |
| `ADG_SOAR_JWT_ALGORITHM` | `HS256` | JWT algorithm |
| `ADG_SOAR_MTLS_REQUIRED` | `true` | Enforce mTLS header |
| `ADG_SOAR_RATE_LIMIT` | `60/minute` | Rate limit |
| `ADG_SOAR_AUDIT_LOG_PATH` | `./state/audit.log` | Audit log |
| `ADG_SOAR_OTLP_ENDPOINT` | `http://otel-collector:4317` | OTel endpoint |
| `ADG_SOAR_VAULT_ADDR` | — | Vault address |
| `ADG_SOAR_VAULT_TOKEN` | — | Vault token |
| `ADG_SOAR_VAULT_SECRET_PATH` | — | Vault secret path |
| `ADG_SOAR_SLACK_WEBHOOK_URL` | — | Slack incoming webhook |
| `ADG_SOAR_PAGERDUTY_ROUTING_KEY` | — | PagerDuty Events API v2 key |
| `ADG_SOAR_JIRA_URL` | — | Jira base URL |
| `ADG_SOAR_JIRA_USER` | — | Jira username |
| `ADG_SOAR_JIRA_TOKEN` | — | Jira API token |
| `ADG_SOAR_JIRA_PROJECT` | — | Jira project key |
| `ADG_SOAR_AD_SERVER` | — | AD LDAP server |
| `ADG_SOAR_AD_USER` | — | AD bind user |
| `ADG_SOAR_AD_PASSWORD` | — | AD bind password |
| `ADG_SOAR_AD_BASE_DN` | — | AD base DN |
| `ADG_SOAR_SENTINELONE_URL` | — | SentinelOne API URL |
| `ADG_SOAR_SENTINELONE_TOKEN` | — | SentinelOne API token |
| `ADG_SOAR_CROWDSTRIKE_URL` | — | CrowdStrike API URL |
| `ADG_SOAR_CROWDSTRIKE_TOKEN` | — | CrowdStrike token |
| `ADG_SOAR_ISE_URL` | — | Cisco ISE base URL |
| `ADG_SOAR_ISE_USER` | — | Cisco ISE username |
| `ADG_SOAR_ISE_PASSWORD` | — | Cisco ISE password |

Vault keys: `jwt_secret`, `slack_webhook_url`, `pagerduty_routing_key`, `jira_token`, `ad_password`, `sentinelone_token`, `crowdstrike_token`, `ise_password`.

### SOAR endpoints

| Method | Path | Role |
|---|---|---|
| GET | `/health` | public |
| POST | `/alerts` | `soar:write` |
| GET | `/playbooks` | `soar:read` |

---

## PCAP Forwarder

| Variable | Default | Purpose |
|---|---|---|
| `PCAP_DIR` | `/pcap` | Directory to watch for PCAP files |
| `KAFKA_BROKER` | `kafka:9092` | Kafka bootstrap server |
| `KAFKA_TOPIC` | `pcap-events` | Kafka topic |

---

## Honeypot apps

| Variable | Purpose |
|---|---|
| `ADG_WEBHOOK_URL` | Controller webhook URL for emitting events |

All fake apps (Jenkins, Grafana, MySQL, SMTP, S3) use `ADG_WEBHOOK_URL` to POST events to the controller.

---

## Helm chart defaults

| Chart | Service port | Notes |
|---|---|---|
| `charts/adg-controller` | 8080 | Override `image`, `replicas` |
| `charts/token-engine` | 8081 | Override `image`, `replicas` |
| `charts/soar-playbooks` | 8090 | Override `image`, `replicas` |
| `charts/honeypots` | varies | Per-honeypot image and port |
