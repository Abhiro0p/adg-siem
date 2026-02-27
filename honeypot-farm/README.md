# Honeypot Farm

High-interaction honeypots and protocol emulators. All honeypots emit structured JSON events to the controller event bus on every interaction. PCAP sidecars capture raw traffic and forward it to Kafka with SHA-256 integrity hashing.

## Honeypot inventory

| Honeypot | Protocol | Port | Implementation |
|---|---|---|---|
| Cowrie | SSH / Telnet | 22, 23 | `infra/k8s/honeypots/cowrie.yaml` |
| Dionaea | SMB / HTTP / FTP / MSSQL | 445, 80, 21, 1433 | `infra/k8s/honeypots/dionaea.yaml` |
| PyRDP | RDP | 3389 | `infra/k8s/honeypots/pyrdp.yaml` |
| Fake Jenkins | HTTP | 8080 | `apps/fake-jenkins/` |
| Fake Grafana | HTTP | 3000 | `apps/fake-grafana/` |
| Fake MySQL | TCP | 3306 | `apps/fake-mysql/` |
| Fake SMTP | TCP | 25 | `apps/fake-smtp/` |
| Fake S3 | HTTP | 9000 | `apps/fake-s3/` |
| Samba | SMB | 445 | `infra/k8s/honeypots/samba.yaml` |

## Fake applications

### Fake Jenkins (`apps/fake-jenkins/`)
- Renders pixel-accurate Jenkins 2.401.3 login page (dark and light themes)
- Sets `X-Jenkins: 2.401.3`, `X-Hudson: 1.395`, and `Server: Jetty(9.4.z-SNAPSHOT)` headers
- Logs every credential attempt and redirects to `/loginError`
- Emits JSON event to controller webhook on each auth attempt

### Fake Grafana (`apps/fake-grafana/`)
- Renders Grafana v9.5.3 dark-theme login page
- Returns `{"database":"ok","version":"9.5.3"}` from `/api/health`
- Returns 401 from `/api/dashboards/home` to simulate auth gate
- Full security header set (HSTS, CSP, nosniff, etc.)

### Fake MySQL (`apps/fake-mysql/`)
- Sends real MySQL Protocol v10 binary handshake packet
- Parses client handshake response and extracts username
- Returns `ER_ACCESS_DENIED_ERROR` (errno 1045) after logging credentials
- Emits JSON event with captured username and client capabilities

### Fake SMTP (`apps/fake-smtp/`)
- Full SMTP dialogue: EHLO/HELO, AUTH LOGIN/PLAIN, MAIL FROM, RCPT TO, DATA, STARTTLS, QUIT
- Decodes BASE64-encoded AUTH credentials and logs them
- Sanitises all input before logging
- Emits JSON event with sender, recipients, and decoded credentials

### Fake S3 (`apps/fake-s3/`)
- AWS S3 XML REST API: `GET /` (list buckets), `GET /{bucket}` (list objects), object ops
- Extracts AWS access key from `Authorization: AWS4-HMAC-SHA256 Credential=<key>/...` header
- Returns accurate S3 XML error responses (`NoSuchBucket`, `AccessDenied`, `NoSuchKey`)
- Sets `Server: AmazonS3` and `x-amz-request-id` headers for realism

## PCAP forwarder (`pcap-forwarder/`)

Sidecar process that watches a PCAP directory and forwards files to Kafka.

- SHA-256 integrity hash included in every Kafka message envelope
- Kafka producer with 10-retry exponential backoff (up to 60 s)
- Per-message 5-retry send with backoff
- `.forwarded` persistence file prevents duplicate forwarding across restarts
- Files exceeding 50 MB are skipped and marked as seen
- Envelope format: `{filename, sha256, size_bytes, ts, data}`

## Synthetic data (`data/`)

Realistic fake users, secrets, and files mounted into honeypots to increase interaction depth. Generate with `scripts/seed_data.py`.

## Kubernetes deployment

Each honeypot manifest (`infra/k8s/honeypots/*.yaml`) includes:
1. The honeypot container
2. A `tcpdump` sidecar writing PCAPs to an `emptyDir` volume at `/pcap`
3. A `pcap-forwarder` sidecar forwarding PCAPs to Kafka

```bash
kubectl apply -f infra/k8s/honeypots/namespace.yaml
kubectl apply -f infra/k8s/honeypots/networkpolicy.yaml
kubectl apply -f infra/k8s/honeypots/
```

## Event format

Every honeypot emits events in this format:

```json
{
  "event_type": "honeypot_auth",
  "honeypot": "fake-mysql",
  "src_ip": "10.0.1.50",
  "src_port": 54321,
  "username": "root",
  "timestamp": "2025-01-01T00:00:00Z",
  "session_id": "abc123"
}
```
