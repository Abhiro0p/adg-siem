# Atomic Red Team Validation

## Setup

```bash
# Install Invoke-AtomicRedTeam on a lab Windows host
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser
Import-Module invoke-atomicredteam

# Or use the CLI runner on Linux
pip install atomic-operator
```

Point tests at honeypot service IPs, not production systems. Run from a lab host in a segmented test subnet that the honeypots can see.

## Test sequence

### T1046 — Network Service Scanning

```bash
# Linux
nmap -sV -p 22,25,80,443,445,3306,3389,8080,3000,9000 <honeypot-ip>

# Atomic
Invoke-AtomicTest T1046 -TestNumbers 1
```

**Expected ADG response**:
- `port_scan` event fires in controller
- Rule `port-scan-detected` triggers (if configured)
- Lure deployed for most-scanned port
- Alert in SIEM with `T1046` technique, `reconnaissance` kill-chain phase

---

### T1110.003 — Brute Force: Password Spraying

```bash
# Target fake-SMTP
smtp-user-enum -M VRFY -U usernames.txt -t <honeypot-ip> -p 25

# Target fake-MySQL
hydra -L users.txt -P passwords.txt mysql://<honeypot-ip>

# Target Cowrie SSH
hydra -L users.txt -P passwords.txt ssh://<honeypot-ip>
```

**Expected ADG response**:
- Multiple `honeypot_auth` events
- Threshold rule fires after N attempts (configure `count` and `window_seconds`)
- Alert with `T1110.003`, `exploitation` kill-chain phase
- SOAR `page_oncall` fires if severity is `high`

---

### T1021.004 — Remote Services: SSH

```bash
ssh root@<cowrie-ip>  # will connect to Cowrie
# Try any credentials
```

**Expected ADG response**:
- Full session transcript captured by Cowrie
- PCAP captured by sidecar and forwarded to Kafka with SHA-256
- Alert with `T1021.004`, `lateral-movement` kill-chain phase

---

### T1190 — Exploit Public-Facing Application

```bash
# Target fake Jenkins
curl http://<jenkins-ip>:8080/j_acegi_security_check \
  -d "j_username=admin&j_password=admin123"

# Target fake Grafana
curl -X POST http://<grafana-ip>:3000/login \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}'
```

**Expected ADG response**:
- Auth attempt event emitted to controller
- Alert with `T1190`, `initial-access` kill-chain phase
- Realism score includes user agent and credential breakdown

---

### T1530 — Data from Cloud Storage

```bash
# Target fake S3
aws s3 ls s3://corp-backups \
  --endpoint-url http://<s3-ip>:9000 \
  --no-verify-ssl

aws s3 cp s3://corp-backups/secrets.txt - \
  --endpoint-url http://<s3-ip>:9000
```

**Expected ADG response**:
- AWS access key extracted from Authorization header
- Alert emitted with extracted key ID
- Alert with `T1530`, `collection` kill-chain phase

---

### T1078.004 — Valid Accounts: Cloud

Use an AWS key breadcrumb seeded on an endpoint:

```bash
AWS_ACCESS_KEY_ID=AKIA... AWS_SECRET_ACCESS_KEY=... aws sts get-caller-identity
```

**Expected ADG response**:
- Token engine `/access/{token_id}` callback fires (if using canarytoken-style token)
- Alert with src_ip, timestamp, and AbuseIPDB enrichment

---

## Validation checklist

After running all tests:

```bash
# Verify lures deployed
curl http://controller:8080/lures -H "Authorization: Bearer $JWT" | jq '.'

# Verify MITRE coverage in recent alerts
# (check SIEM for techniques: T1046, T1110.003, T1021.004, T1190, T1530, T1078.004)

# Verify PCAP integrity
# kafka-console-consumer --topic pcap-events --from-beginning | jq '.sha256'

# Verify SOAR actions fired
cat soar-playbooks/state/action_audit.log | jq 'select(.action=="notify_slack")'
```
