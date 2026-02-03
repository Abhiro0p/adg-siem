# Token Engine

Generates cryptographically realistic honeytokens and logs every access event to the event bus and SIEM webhook. Supports 15 credential types with format-accurate values generated using `secrets.choice` — no Faker patterns that analysts could distinguish from real credentials.

## Endpoints

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/health` | public | Liveness/readiness probe |
| POST | `/tokens` | `token:write` | Create honeytoken (`token_type`, optional `ttl_hours`, `metadata`) |
| GET | `/tokens` | `token:read` | List all tokens |
| POST | `/access/{token_id}` | `token:write` | Log an access event for a token |
| POST | `/rotate` | `token:admin` | Rotate (revoke + regenerate) tokens by type |
| GET | `/bundle` | `token:read` | Generate a 13-file decoy credential bundle |
| GET | `/metrics` | public | Prometheus metrics |

## Supported token types

Pass the `token_type` string exactly as shown when calling `POST /tokens`.

| Type key | Format |
|---|---|
| `ssh_key` | RSA public key (`ssh-rsa AAAA...`) |
| `aws_key` | `AKIA` + 16 uppercase alphanumeric chars + 40-char secret |
| `aws_session_token` | STS-style session token with expiry |
| `aws_cli_config` | INI-format `[default]` credentials file |
| `azure_key` | JSON with `clientId`, `tenantId`, `subscriptionId`, `clientSecret` |
| `gcp_key` | Full GCP service account JSON with PEM-structured private key |
| `github_pat` | `ghp_` + 36 alphanumeric chars |
| `slack_token` | `xoxb-` + realistic segment pattern |
| `k8s_token` | 3-part JWT: header/payload with k8s claims, random signature |
| `git_credential` | `https://user:token@github.com` |
| `docker_config` | `{"auths": {...}}` JSON with base64 auth |
| `db_connection_string` | `postgresql://user:password@host/db` |
| `env_api_key` | Random prefix (`sk_`, `pk_`, `api_`, etc.) + URL-safe token |
| `browser_password` | Username + password pair (simulates browser-saved credential) |
| `rdp_history` | RDP MRU entry with hostname and username |

## Decoy file bundle (`/bundle`)

Returns a ZIP containing 13 files matching common credential locations:

- `.aws/credentials` and `.aws/config`
- `gcp_service_account.json`
- `azure_credentials.json`
- `id_rsa_decoy` (SSH private key)
- `known_hosts`
- `.env` (API_KEY, DATABASE_URL, JWT_SECRET, REDIS_URL)
- `passwords.txt`
- `config.yaml`
- `.docker/config.json`
- `k8s_token`
- `.git-credentials`
- `.ssh/config`

## Running locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8081 --reload
```

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ADG_TOKEN_JWT_SECRET` | — | JWT signing secret (required) |
| `ADG_TOKEN_DB_PATH` | `./state/tokens.db` | SQLite token store path |
| `ADG_TOKEN_WEBHOOK_URL` | — | SIEM webhook for access events |
| `ADG_TOKEN_VAULT_ADDR` | — | HashiCorp Vault address |
| `ADG_TOKEN_VAULT_TOKEN` | — | Vault token |
| `ADG_TOKEN_VAULT_SECRET_PATH` | — | Vault secret path |
| `ADG_TOKEN_OTLP_ENDPOINT` | `http://otel-collector:4317` | OpenTelemetry collector |
| `ADG_TOKEN_RATE_LIMIT` | `60/minute` | slowapi rate limit |
| `ADG_TOKEN_MTLS_REQUIRED` | `true` | Enforce mTLS verify header |
| `ADG_TOKEN_AUDIT_LOG_PATH` | `./state/audit.log` | Action audit log path |
