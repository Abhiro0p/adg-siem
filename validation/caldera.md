# CALDERA Validation

MITRE CALDERA runs multi-step adversary operations that more closely simulate real attacker behaviour than individual Atomic tests. Use CALDERA to validate end-to-end detection across multiple ATT&CK tactics.

## Setup

```bash
# Deploy CALDERA server in lab environment
git clone https://github.com/mitre/caldera.git
cd caldera
pip install -r requirements/go.txt
python server.py --insecure --fresh

# Access UI at http://localhost:8888 (default creds: admin/admin)
```

Deploy a CALDERA agent (`sandcat`) on a lab host in the test subnet:

```bash
# On the lab host (Linux)
curl -s -X POST http://caldera-server:8888/file/download \
  -d '{"file":"sandcat.go-linux","platform":"linux"}' \
  -H "KEY:CALDERA_KEY" | chmod +x - && ./sandcat \
  -server http://caldera-server:8888 -group honeypot-lab
```

## Operations to run

### Operation 1: Discovery

**Goal**: validate detection of reconnaissance techniques.

**Ability sequence**:
1. `T1046` — Network Service Discovery: scan honeypot subnet for open ports 22, 25, 80, 445, 3306, 3389, 8080, 3000, 9000
2. `T1016` — System Network Configuration Discovery: enumerate routes and interfaces
3. `T1018` — Remote System Discovery: ping sweep the subnet

**Expected detections**:
- Controller receives `port_scan` events from honeypot interactions
- `reconnaissance` kill-chain phase present in all alerts
- Coverage heatmap (`/coverage`) updated with discovered subnets

---

### Operation 2: Credential Access

**Goal**: validate honeytoken and honeypot auth detection.

**Ability sequence**:
1. `T1003` — OS Credential Dumping: read `/etc/shadow`, `LSASS` dump (simulated)
2. `T1552.001` — Credentials in Files: read `/opt/decoy/.env`, `~/.aws/credentials`, `~/.git-credentials`
3. `T1110.001` — Brute Force: attempt auth on fake-MySQL and Cowrie SSH using found credentials
4. `T1528` — Steal Application Access Token: use extracted API key from `.env`

**Expected detections**:
- File read triggers token engine access event (canarytoken callback)
- Brute force threshold rule fires after N attempts
- Alerts with `T1552.001`, `T1110.001`, `T1528` technique mappings
- `credential-access` kill-chain phase in alerts

---

### Operation 3: Lateral Movement

**Goal**: validate detection of movement using harvested credentials.

**Ability sequence**:
1. `T1021.004` — Remote Services: SSH: use harvested SSH key against Cowrie
2. `T1021.002` — Remote Services: SMB: connect to Dionaea or Samba
3. `T1021.001` — Remote Services: RDP: connect to PyRDP

**Expected detections**:
- Each honeypot connection emits event to controller
- MITRE tactic `lateral-movement` in all alerts
- SOAR `disable_ad_account` fires if AD decoy account used
- SOAR `isolate_sentinelone` fires for source host

---

### Operation 4: Collection and Exfiltration

**Goal**: validate detection of data staging and exfiltration techniques.

**Ability sequence**:
1. `T1530` — Data from Cloud Storage: enumerate fake S3 buckets and download objects
2. `T1560` — Archive Collected Data: tar the decoy files found
3. `T1048` — Exfiltration over Alternative Protocol: attempt DNS TXT record exfil

**Expected detections**:
- S3 enumeration triggers alerts with access key extraction
- Exfiltration attempt triggers `objectives` kill-chain phase
- SOAR `block_ip_firewall` fires for exfil destination

---

## Verifying results

After each operation completes, collect evidence:

```bash
# 1. SIEM alerts (check your Splunk/Elastic/Sentinel instance)

# 2. Lures deployed
curl http://controller:8080/lures -H "Authorization: Bearer $JWT" | jq '.'

# 3. Coverage heatmap
curl http://controller:8080/coverage -H "Authorization: Bearer $JWT" | jq '.'

# 4. SOAR actions executed
cat soar-playbooks/state/action_audit.log | jq '{action, subject, outcome, timestamp}'

# 5. PCAP artifacts in Kafka
# Check pcap-events topic consumer for files with valid sha256

# 6. ATT&CK technique coverage
curl http://controller:8080/rules -H "Authorization: Bearer $JWT" \
  | jq '.[].tags | select(. != null) | .[]' | sort | uniq
```

## CALDERA adversary profile

Save as `caldera/data/adversaries/adg-validation.yml`:

```yaml
id: adg-validation
name: ADG Validation Adversary
description: End-to-end deception grid validation
atomic_ordering:
  - T1046    # Discovery
  - T1552.001  # Credential access via files
  - T1110.001  # Brute force
  - T1021.004  # Lateral movement SSH
  - T1530    # Collection from fake S3
  - T1048    # Exfiltration
```
