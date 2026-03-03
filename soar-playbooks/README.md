# SOAR Playbooks

Webhook-driven SOAR response engine. Receives alert webhooks from the controller, evaluates YAML playbooks, and executes automated response actions across Slack, PagerDuty, Jira, Active Directory, firewalls, and EDR platforms.

## Endpoints

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/health/live` | public | Liveness probe |
| GET | `/health` | public | Legacy health alias |
| POST | `/alerts` | `soar:write` | Receive controller alert webhooks |
| GET | `/playbooks` | `soar:read` | List loaded playbooks and their actions |
| GET | `/metrics` | public | Prometheus metrics |

## Response actions (12 total)

Use these action names exactly in playbook YAML definitions.

| Action key | Implementation |
|---|---|
| `notify_slack` | POST to Slack webhook with formatted Block Kit message |
| `page_oncall` | PagerDuty Events API v2 (`/v2/enqueue`) with severity mapping |
| `create_jira_ticket` | Jira REST API (`/rest/api/2/issue`) with Jira wiki markup description |
| `disable_ad_account` | ldap3 MODIFY — sets `userAccountControl` to 514 (disabled) |
| `block_ip_firewall` | Appends to `blocked_ips.log`; optionally POSTs to WAF webhook |
| `sentinelone_isolate` | Resolves IP to agent ID via SentinelOne API, then calls disconnect |
| `crowdstrike_isolate` | CrowdStrike Falcon API network containment |
| `ise_quarantine` | Cisco ISE CoA quarantine via REST API |
| `defender_isolate` | Microsoft Defender API network isolation |
| `quarantine_host` | Generic host quarantine (writes quarantine log entry) |
| `snapshot_honeypot` | Archives honeypot state with SHA-256 evidence integrity checksum |
| `extract_iocs` | Parses alert fields for IPs, domains, hashes; writes IOC JSONL log |

## Playbook format

```yaml
# playbooks/default.yaml
- name: high-severity-response
  trigger:
    severity: [high, critical]
  actions:
    - notify_slack
    - page_oncall
    - create_jira_ticket
    - snapshot_honeypot

- name: lateral-movement-response
  trigger:
    tags: [lateral_movement]
  actions:
    - disable_ad_account
    - sentinelone_isolate
    - block_ip_firewall
```

## Running locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8090 --reload
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ADG_SOAR_JWT_SECRET` | — | JWT signing secret (required) |
| `ADG_SOAR_SLACK_WEBHOOK_URL` | — | Slack incoming webhook URL |
| `ADG_SOAR_PAGERDUTY_ROUTING_KEY` | — | PagerDuty Events API routing key |
| `ADG_SOAR_JIRA_URL` | — | Jira base URL |
| `ADG_SOAR_JIRA_USER` | — | Jira username |
| `ADG_SOAR_JIRA_TOKEN` | — | Jira API token |
| `ADG_SOAR_JIRA_PROJECT` | — | Jira project key |
| `ADG_SOAR_AD_SERVER` | — | AD LDAP server |
| `ADG_SOAR_AD_USER` | — | AD bind user |
| `ADG_SOAR_AD_PASSWORD` | — | AD bind password |
| `ADG_SOAR_AD_BASE_DN` | — | AD base DN |
| `ADG_SOAR_SENTINELONE_URL` | — | SentinelOne management API URL |
| `ADG_SOAR_SENTINELONE_TOKEN` | — | SentinelOne API token |
| `ADG_SOAR_CROWDSTRIKE_URL` | — | CrowdStrike API URL |
| `ADG_SOAR_CROWDSTRIKE_TOKEN` | — | CrowdStrike token |
| `ADG_SOAR_ISE_URL` | — | Cisco ISE base URL |
| `ADG_SOAR_ISE_USER` | — | Cisco ISE username |
| `ADG_SOAR_ISE_PASSWORD` | — | Cisco ISE password |
| `ADG_SOAR_VAULT_ADDR` | — | HashiCorp Vault address |
| `ADG_SOAR_OTLP_ENDPOINT` | `http://otel-collector:4317` | OpenTelemetry collector |
| `ADG_SOAR_MTLS_REQUIRED` | `true` | Enforce mTLS verify header |
| `ADG_SOAR_AUDIT_LOG_PATH` | `./state/audit.log` | Action audit log path |
