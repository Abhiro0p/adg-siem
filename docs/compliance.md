# Compliance Mapping

ADG generates and preserves the evidence required to satisfy common security control frameworks.

## NIST SP 800-53 (Rev 5)

| Control family | Control | ADG implementation |
|---|---|---|
| AU — Audit and Accountability | AU-2 Event Logging | Structured JSON audit logs on all services; action-level log with `request_id` correlation |
| AU — Audit and Accountability | AU-3 Content of Audit Records | Each record includes: timestamp, subject, action, resource, outcome, request ID |
| AU — Audit and Accountability | AU-9 Audit Information Protection | Audit log path is write-only from within service; ship to immutable SIEM index |
| AU — Audit and Accountability | AU-11 Audit Retention | 14-day retention CronJob (`infra/k8s/retention/log-retention.yaml`); extend as required |
| AC — Access Control | AC-2 Account Management | AD decoy account lifecycle (create, enable, disable) via `/ad/*` endpoints |
| AC — Access Control | AC-3 Access Enforcement | JWT RBAC with roles `controller:read/write/admin`, `token:read/write/admin`, `soar:write` |
| AC — Access Control | AC-17 Remote Access | mTLS enforcement via ingress + `X-SSL-Client-Verify` header |
| SC — System and Communications | SC-8 Transmission Confidentiality | TLS on all endpoints; HSTS header enforced |
| SC — System and Communications | SC-28 Protection at Rest | Credentials stored in Vault or Kubernetes Secrets; sensitive fields redacted before SIEM emission |
| SI — System and Information Integrity | SI-3 Malware Protection | PCAP capture + SHA-256 integrity hashing; evidence snapshots with checksums |
| SI — System and Information Integrity | SI-4 System Monitoring | Real-time event ingestion, MITRE ATT&CK mapping, behavioral baseline anomaly detection |
| SI — System and Information Integrity | SI-7 Software Integrity | Image signing (`scripts/sign_images.sh`); SBOM generation (`scripts/generate_sbom.sh`) |
| RA — Risk Assessment | RA-5 Vulnerability Scanning | `scripts/scan_vulns.sh` for container image CVE scanning |

## SOC 2 Type II

| Criteria | Control | ADG implementation |
|---|---|---|
| CC6.1 Logical Access | Authentication | JWT with required claims (`sub`, `exp`, `iat`, `jti`) + mTLS |
| CC6.1 Logical Access | Authorisation | RBAC roles enforced on every endpoint |
| CC6.1 Logical Access | Credential management | HashiCorp Vault integration; token rotation CronJob |
| CC6.6 Logical Access Restrictions | Token revocation | Per-JTI blacklist with TTL; `/auth/revoke` endpoint |
| CC7.1 Threat Detection | Monitoring | Continuous event ingestion; behavioral anomaly detection; MITRE mapping |
| CC7.2 Monitoring of System Components | Health checks | `/health/ready` checks Postgres, Redis, Vault, SIEM; Prometheus metrics |
| CC7.3 Evaluation of Security Events | Alerting | Multi-SIEM fan-out with retry; SOAR automated response |
| CC9.2 Risk Mitigation | Deception | Honeytokens and honeypots generate high-fidelity early-warning signals |

## Evidence artifacts

| Artifact | How to generate | Location |
|---|---|---|
| SBOM | `scripts/generate_sbom.sh` | `sbom.json` |
| Vulnerability scan report | `scripts/scan_vulns.sh` | `vuln-report.json` |
| Signed image digests | `scripts/sign_images.sh` | Container registry |
| Audit logs | Automatic, per service | `ADG_*_AUDIT_LOG_PATH` → SIEM |
| Alert records | Automatic, per event | SIEM index |
| PCAP integrity hashes | Automatic, per forwarder | Kafka `pcap-events` topic |
| SOAR action evidence | Automatic, per action | `state/*.log` |
| Test run results | `pytest --junitxml=results.xml` | `results.xml` |

## CI/CD controls

The following checks run on every commit:

- **Lint**: `ruff check .` — enforces consistent code style
- **Type checks**: `mypy app/` — catches type errors before runtime
- **Unit tests**: `pytest tests/ -v` — 39 tests, all must pass
- **Secret scan**: pre-commit hook or CI step to prevent credential commits

## Recommendations for audit readiness

1. Store SBOMs and scan reports in an immutable artifact repository (e.g., S3 with Object Lock)
2. Enforce image signature verification in your Kubernetes admission controller (OPA/Gatekeeper or Kyverno)
3. Ship all audit logs and action logs to an append-only SIEM index with role-based write restriction
4. Document the token rotation schedule and retain rotation records for at least 12 months
5. Run the CALDERA/Atomic Red Team validation plan quarterly and retain the evidence collection output
6. Review `/rules` governance approvals before each rule reload and retain the approval records
