# Data Flow

End-to-end lifecycle of a deception event, from attacker interaction to SOAR response.

## 1. Attacker interaction

An attacker discovers and interacts with a breadcrumb credential or honeypot service:

- **Breadcrumb**: uses an AWS key, SSH key, or k8s token seeded by the Ansible breadcrumb role → token engine `/access/{token_id}` is called (canarytoken-style callback)
- **Honeypot**: connects to fake MySQL, SMTP, S3, Jenkins, Grafana, Cowrie, Dionaea, or PyRDP → honeypot emits a structured JSON event

## 2. Event emission

Every honeypot and the token engine emit events in a common schema:

```json
{
  "event_type": "honeypot_auth",
  "honeypot": "fake-mysql",
  "src_ip": "203.0.113.50",
  "src_port": 54321,
  "dst_port": 3306,
  "username": "root",
  "timestamp": "2025-01-01T12:00:00Z",
  "session_id": "abc123",
  "request_id": "req-uuid"
}
```

Events are POSTed directly to the controller `/events` endpoint or published to the Redis Streams bus (`adg-events` stream).

## 3. Bus delivery

The controller consumes from the bus:

- **In-memory mode**: async queue with backpressure (drops oldest at capacity, logs warning)
- **Redis Streams mode**: consumer group `adg-controller` / `controller-0`; on startup re-delivers pending unACKed messages, then switches to live (`>`); every message ACKed with `XACK` after processing; reconnects automatically on error

PCAP sidecars write to Kafka `pcap-events` topic with SHA-256 integrity hash in the envelope.

## 4. Rule evaluation

The controller evaluates the event against all enabled rules:

1. **Schema validation** — checks required fields and operator names
2. **Condition matching** — evaluates `when` conditions and `condition_groups` (AND/OR)
3. **Threshold check** — for `threshold` operators, records the event key in a sliding window and counts occurrences in `window_seconds`
4. **Approval check** — skips rules that require approvers and have none set

## 5. Enrichment (parallel)

For events with a `src_ip`, the controller calls `enrich_ip()` asynchronously:

- **GeoIP** (ip-api.com): country, city, org, ISP, timezone, lat/lon
- **Reverse DNS**: hostname via `gethostbyaddr` in a thread executor
- **AbuseIPDB**: abuse confidence score, total reports, usage type
- **AlienVault OTX**: pulse count (threat intelligence hits)

Private/loopback/reserved IPs are skipped. Enrichment is best-effort — failures don't block alert delivery.

## 6. MITRE ATT&CK mapping

Rule tags matching `T\d{4}` patterns are looked up in the technique map (100+ entries):

- Tactic (e.g., `initial-access`, `lateral-movement`)
- Kill-chain phase (e.g., `reconnaissance`, `exploitation`, `objectives`)
- Technique description and direct URL to attack.mitre.org
- Deduplicated and sorted kill-chain phases attached to the alert

## 7. Realism scoring

The `BaselineTracker` records every event and computes z-scores on bucketed 10-second windows. Anomalous bursts are flagged. The `realism_score()` function also applies a multi-factor breakdown:

- **Network**: high-value port (+0.20), src_ip present (+0.10), known protocol (+0.05)
- **Credential**: username present (+0.15), password present (+0.10)
- **Behaviour**: user agent (+0.10), scanner UA pattern (+0.10), payload data (+0.05)
- **Context**: matching event type (+0.10), enrichment data present (+0.05)

Score is clamped to [0, 1] and classified as `definite_decoy`, `likely_decoy`, `ambiguous`, or `unlikely_decoy`.

## 8. Alert construction and redaction

`build_alert()` assembles the alert with all enrichment, MITRE data, and realism score. Before emission, `redact_dict()` masks:

- 30+ sensitive field names (password, token, api_key, private_key, etc.)
- AWS access keys (`AKIA...`)
- PEM headers
- GitHub/GitLab PATs
- Slack tokens
- JWTs
- Bearer tokens
- Credit card numbers

## 9. SIEM fan-out

The `MultiEmitter` fires all configured emitters in parallel with `asyncio.gather`. Individual emitter failures are logged but do not block others. Each emitter retries with [1, 3, 7] s backoff before giving up.

| Emitter | Auth mechanism |
|---|---|
| Webhook | HMAC-SHA256 `X-ADG-Signature` header |
| Splunk HEC | `Authorization: Splunk <token>` |
| Elasticsearch | `Authorization: ApiKey <key>` |
| Microsoft Sentinel | `Authorization: SharedKey <workspace>:<HMAC-SHA256>` |
| Sumo Logic | `X-Sumo-Category: adg/alerts` |
| Datadog | `DD-API-KEY: <key>` |

## 10. SOAR response

The SOAR playbook service receives the alert webhook, matches it against playbook triggers (by severity, tags, event type), and executes configured actions in order. Each action is independently retried and logged. The audit log records the outcome of every action with the originating `request_id`.

## 11. Orchestration

Simultaneously with SIEM delivery, the controller orchestrator may:

- Deploy a new lure (honeypot pod via Kubernetes API, or dry-run log)
- Update DNS to point a decoy hostname at the honeypot
- Create or disable an AD decoy account
- Record the deployment in the state store with TTL for automatic reaper cleanup
