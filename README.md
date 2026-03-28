# Adaptive Deception Grid (ADG)

A production-grade, modular active deception platform for blue teams. ADG deploys high-fidelity honeytokens, breadcrumb credentials, and interactive honeypots across your environment, then correlates every interaction through a rule engine with MITRE ATT&CK mapping, threat-intel enrichment, and automated SOAR response.

## Repository layout

| Directory | Purpose |
|---|---|
| `controller/` | Adaptive deception controller — rule engine, MITRE mapping, enrichment, orchestration |
| `token-engine/` | Honeytoken generation (15 credential types) and access-event logging |
| `soar-playbooks/` | Webhook-driven SOAR response engine (12 actions) |
| `honeypot-farm/` | High-interaction honeypots: Cowrie, Dionaea, PyRDP, fake Jenkins/Grafana/MySQL/SMTP/S3 |
| `breadcrumbs/` | Ansible breadcrumb deployment — AWS, GCP, Azure, k8s, SSH, Docker, git credentials |
| `dashboards/` | Grafana/Kibana dashboard definitions |
| `infra/` | Kubernetes manifests and Terraform modules |
| `charts/` | Helm charts for all services |
| `validation/` | Atomic Red Team and CALDERA validation plans |
| `docs/` | Architecture, data flow, configuration, deployment, operations, security, testing |

## Core capabilities

### Detection
- **Rule engine** — 20 condition operators including stateful sliding-window threshold detection, subnet matching, regex, range, and OR/AND condition groups
- **MITRE ATT&CK** — 100+ technique and sub-technique mappings with tactic, kill-chain phase, and technique description; enriched alerts link directly to attack.mitre.org
- **Threat intelligence** — GeoIP (ip-api.com), reverse DNS, AbuseIPDB confidence score, AlienVault OTX pulse count gathered in parallel per alert
- **Behavioral baseline** — z-score anomaly detection on bucketed event counts; flags statistical outliers without static thresholds
- **Deception realism scoring** — multi-factor score (network, credential, behaviour, context) with sigmoid confidence; classifies events as `definite_decoy`, `likely_decoy`, `ambiguous`, or `unlikely_decoy`

### Tokens and breadcrumbs
- **15 token types**: AWS access key + secret, GCP service account JSON, Azure service principal JSON, k8s service account JWT, GitHub PAT, GitLab PAT, generic API key, JWT, SSH private key, database URL, Slack token, Docker config, AWS CLI config, git credential
- **Ansible breadcrumb roles** for Linux and Windows: seeds AWS credentials, SSH keys, kubeconfig, Docker config, GCP service account, `.env`, `config.yaml`, `.git-credentials`, browser password CSV, and a decoy in-memory service

### Honeypots
- **Cowrie** (SSH/Telnet), **Dionaea** (SMB/HTTP/FTP), **PyRDP** (RDP)
- **Fake Grafana** (v9.5.3) and **Fake Jenkins** (2.401.3) — pixel-accurate login pages, realistic headers, event emission
- **Fake MySQL** — Protocol v10 handshake, captures usernames, returns ER_ACCESS_DENIED_ERROR (1045)
- **Fake SMTP** — full SMTP dialogue (EHLO, AUTH LOGIN/PLAIN, MAIL, RCPT, DATA, STARTTLS, QUIT), decodes BASE64 credentials
- **Fake S3** — AWS S3 XML REST API, extracts access key from Authorization header, returns believable bucket listings and object errors
- **PCAP forwarder** — SHA-256 integrity hash, 5-retry Kafka producer with exponential backoff, `.forwarded` persistence, 50 MB file size limit

### SOAR response (12 actions)
`notify_slack`, `page_oncall`, `create_jira_ticket`, `disable_ad_account`, `block_ip_firewall`, `sentinelone_isolate`, `crowdstrike_isolate`, `ise_quarantine`, `defender_isolate`, `quarantine_host`, `snapshot_honeypot` (SHA-256 evidence integrity), `extract_iocs`

### SIEM delivery
Multi-emitter fan-out with exponential retry: **webhook** (HMAC-SHA256 signature), **Splunk HEC**, **Elasticsearch**, **Microsoft Sentinel** (SharedKey HMAC), **Sumo Logic**, **Datadog**

### DNS providers
PowerDNS REST API, RFC2136 (TSIG), AWS Route53 (boto3), Cloudflare REST API — all with input allowlist sanitisation preventing DNS injection

## Security posture
- JWT authentication with required `sub`, `exp`, `iat`, `jti` claims; per-token blacklist with lazy TTL purge
- RBAC roles: `controller:read/write/admin`, `token:read/write/admin`, `soar:write`
- mTLS enforcement via ingress header (`X-SSL-Client-Verify`)
- Security headers on every response: HSTS, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Cache-Control: no-store`
- Sensitive field redaction before any SIEM emission (30+ field names + value-pattern regexes for AWS keys, PEM headers, GitHub/GitLab PATs, Slack tokens, JWTs, Bearer tokens, credit cards)
- Action-level audit log with `request_id` correlation across services
- HashiCorp Vault integration for all credentials

## Observability
- Prometheus metrics via FastAPI Instrumentator (`/metrics`)
- OpenTelemetry distributed tracing to any OTLP collector
- Structured JSON logs (python-json-logger) on every service
- `/health/live` (liveness) and `/health/ready` (readiness — checks Postgres, Redis, Vault, downstream SIEM) on the controller
- Request ID (`X-Request-ID`) propagated through all logs and responses

## Test suite (43 tests, all passing)
`controller/tests/` (39 tests) covers rule operators, stateful threshold detection, OR/AND condition groups, subnet conditions, deception scoring, coverage mapping, baseline tracker, MITRE kill-chain mapping, sensitive data redaction, and SQLite state store. `token-engine/tests/` (4 tests) covers token generation, bundle generation, and token rotation.

## Quick start

```bash
# Build and run controller locally
cd controller
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8080

# Run tests
python -m pytest tests/ -v

# Deploy to Kubernetes (see docs/deployment-guide.md)
kubectl apply -f infra/k8s/honeypots/namespace.yaml
kubectl apply -f infra/k8s/honeypots/networkpolicy.yaml
kubectl apply -f infra/k8s/bus/
kubectl apply -f infra/k8s/storage/
kubectl apply -f infra/k8s/honeypots/
```

## Documentation
- [Architecture](docs/architecture.md) — component diagram, trust boundaries, data storage
- [Data flow](docs/data-flow.md) — end-to-end event lifecycle
- [Configuration reference](docs/configuration.md) — all environment variables for every service
- [Deployment guide](docs/deployment-guide.md) — Kubernetes and Helm deployment steps
- [Operations](docs/operations.md) — token rotation, scaling, retention, monitoring
- [Security](docs/security.md) — auth, mTLS, secrets, audit
- [Testing](docs/testing.md) — unit, integration, performance, chaos
- [Runbooks](docs/runbooks.md) — incident response procedures
- [Compliance](docs/compliance.md) — NIST 800-53 / SOC 2 mapping

## Principles
- **Non-impact**: deception artifacts never touch production workloads; all changes are reversible
- **High-fidelity signals**: session transcripts + PCAP + MITRE technique + kill-chain phase + threat-intel enrichment on every alert
- **Secret hygiene**: all credentials flow through Vault or Kubernetes Secrets; never hardcoded
- **Open-source only**: no proprietary licensing required

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

```
Copyright 2026 ADG Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
