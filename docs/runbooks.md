# Runbooks

Incident response procedures for ADG operations. Each runbook identifies the symptom, probable causes, diagnostic steps, and resolution.

---

## Controller unavailable

**Symptoms**: `/health/live` returns non-200, lures not being deployed, no alerts reaching SIEM.

**Diagnose**:
```bash
kubectl get pods -n honeypots -l app=adg-controller
kubectl logs deployment/adg-controller -n honeypots --tail=100
curl http://controller:8080/health/ready
```

**Resolution**:
1. If leader election is enabled, check Redis lock: `redis-cli GET adg-controller-leader`
2. If Postgres unavailable, the controller falls back to SQLite — verify `ADG_STATE_DB_URL`
3. Check Vault connectivity if secrets are loaded from Vault
4. Restart the deployment: `kubectl rollout restart deployment/adg-controller -n honeypots`
5. Confirm pending Redis Stream messages are replayed after restart (`XPENDING adg-events adg-controller`)

---

## Honeytoken access storm

**Symptoms**: Token engine overwhelmed; webhook delivery backing up; SIEM flooded.

**Diagnose**:
```bash
# Check access event rate
curl http://token-engine:8081/tokens -H "Authorization: Bearer $JWT" | jq '.[] | .access_count' | sort -n | tail
# Check HPA status
kubectl get hpa token-engine-hpa -n honeypots
```

**Resolution**:
1. Scale token engine: `kubectl scale deployment/adg-token-engine --replicas=5 -n honeypots`
2. Temporarily increase `ADG_TOKEN_RATE_LIMIT` to shed load from a single source
3. If a specific token is being hammered, revoke it and generate a new one
4. Verify SIEM ingestion pipeline can handle the burst; check Splunk/Elastic queue depth

---

## DNS update failures

**Symptoms**: Lures deployed but DNS not resolving; controller logs show DNS errors.

**Diagnose**:
```bash
kubectl logs deployment/adg-controller -n honeypots | grep "dns"
# Check DNS mode and credentials
kubectl exec deployment/adg-controller -n honeypots -- env | grep ADG_DNS
```

**Resolution**:
1. Validate credentials: test DNS API key against the provider directly
2. For Route53: verify AWS credentials have `route53:ChangeResourceRecordSets` permission
3. For Cloudflare: verify token has `Zone:DNS:Edit` permission and correct zone ID
4. For RFC2136: verify TSIG key name and secret match server configuration
5. Check input sanitisation: ensure hostnames contain only `[a-zA-Z0-9_\-\.]` characters
6. Reload credentials from Vault: restart the controller after updating Vault secrets

---

## SIEM delivery failures

**Symptoms**: Alerts generated (visible in controller logs) but not appearing in SIEM.

**Diagnose**:
```bash
kubectl logs deployment/adg-controller -n honeypots | grep "siem\|emitter\|alert"
# Check network policy allows egress to SIEM
kubectl describe netpol -n honeypots
```

**Resolution**:
1. Verify `ADG_SIEM_URL` / `ADG_ALERT_WEBHOOK_URL` resolves from within the pod
2. Check SIEM token validity (Splunk HEC tokens expire; Sentinel shared keys are permanent)
3. For Sentinel: verify workspace ID and shared key match the Azure portal values
4. For webhook mode: check `ADG_SIEM_WEBHOOK_SECRET` matches the receiver's expected value
5. MultiEmitter logs each emitter's failure independently — one failing emitter does not block others; check which specific emitter is failing
6. Re-process missed alerts from the audit log if delivery failed for an extended window

---

## Redis Streams backlog

**Symptoms**: Events piling up; controller processing lag; `XPENDING` count growing.

**Diagnose**:
```bash
redis-cli XLEN adg-events
redis-cli XPENDING adg-events adg-controller - + 10
redis-cli INFO memory
```

**Resolution**:
1. Scale the controller to increase throughput (requires Postgres state store and Redis bus)
2. If Redis is memory-constrained, set `MAXLEN` on the stream: `redis-cli XTRIM adg-events MAXLEN 50000`
3. Check for a slow enrichment step — AbuseIPDB or OTX calls can block processing; consider setting `ADG_ENRICHMENT_ENABLED=false` temporarily
4. Confirm `ADG_BUS_MODE=redis` is set correctly on all controller replicas

---

## Vault unavailable

**Symptoms**: Controller/token engine/SOAR fail to start; logs show Vault connection errors.

**Resolution**:
1. Check Vault seal status: `vault status`
2. If Vault is sealed, unseal with the required key shares
3. Fall back to Kubernetes Secrets: set `ADG_VAULT_ADDR=""` and supply credentials via env vars directly — restart services
4. After Vault is restored, rotate any credentials that may have been exposed via fallback env vars
5. Re-seed Vault: `vault kv put secret/adg/controller jwt_secret="..." ...`

---

## mTLS failures

**Symptoms**: All requests return 401 with "mTLS verification failed".

**Diagnose**:
```bash
# Check ingress is setting the header
curl -v https://controller.your-domain.com/health/live 2>&1 | grep X-SSL
```

**Resolution**:
1. Verify ingress is configured for client certificate verification and sets `X-SSL-Client-Verify: SUCCESS`
2. Validate client certificate CA chain against the ingress CA configuration
3. For temporary bypass during incident response: `kubectl set env deployment/adg-controller ADG_MTLS_REQUIRED=false -n honeypots`
4. Restore mTLS as soon as possible and rotate any JWTs issued during the bypass window

---

## Honeypot not emitting events

**Symptoms**: Honeypot receives connections (confirmed in pod logs) but no events appear in controller.

**Diagnose**:
```bash
kubectl logs deployment/fake-mysql -n honeypots
kubectl exec deployment/fake-mysql -n honeypots -- env | grep ADG_WEBHOOK_URL
# Check network policy allows honeypot → controller
kubectl describe netpol -n honeypots
```

**Resolution**:
1. Verify `ADG_WEBHOOK_URL` points to the controller service DNS name within the cluster
2. Confirm the network policy permits egress from honeypot pods to the controller service
3. Check controller `/events` endpoint is accepting requests (authentication, rate limiting)
4. Restart the honeypot pod: `kubectl rollout restart deployment/fake-mysql -n honeypots`

---

## SOAR action failures

**Symptoms**: Controller alerts delivered but SOAR actions not executing (no Slack/PD/Jira activity).

**Diagnose**:
```bash
kubectl logs deployment/adg-soar -n honeypots --tail=100
cat state/action_audit.log | jq 'select(.outcome=="failure")'
```

**Resolution**:
1. Check each integration's credentials independently (Slack, PagerDuty, Jira, AD, SentinelOne)
2. For Jira: verify project key exists and API token has `create issue` permission
3. For SentinelOne: verify the device IP resolves to an agent ID via `/web/api/v2.1/agents`
4. Action failures are logged individually — other actions in the playbook continue executing
5. Re-trigger manually: POST the original alert JSON to `/alerts` after fixing the credential

---

## JWT rejected unexpectedly

**Symptoms**: Valid-looking tokens return 401.

**Resolution**:
1. Confirm the token includes `sub`, `exp`, `iat`, and `jti` claims — all four are required
2. Check clock skew between token issuer and the service (`iat` must not be in the future)
3. Check if the `jti` has been revoked: search the controller logs for the JTI value
4. Verify `ADG_JWT_SECRET` / `ADG_JWT_ALGORITHM` match the issuer's signing key
5. If the secret was rotated, all previously issued tokens are immediately invalid — re-issue
