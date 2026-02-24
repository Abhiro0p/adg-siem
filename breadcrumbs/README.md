# Breadcrumbs

Ansible roles that seed realistic decoy credentials across Linux and Windows endpoints. Every breadcrumb is generated at playbook runtime from the ADG token engine — values are unique per host and per run, and are recorded in the token store for access-event correlation.

## What gets deployed (Linux)

| Location | Content |
|---|---|
| `/etc/profile.d/decoy_env.sh` | `API_KEY`, `GITHUB_TOKEN`, `DATABASE_URL`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` env vars |
| `/root/.aws/credentials` | AWS credentials INI file (access key + secret) |
| `/root/.aws/config` | AWS config (region, output format) |
| `/root/.ssh/id_rsa_corp` | Decoy RSA private key (PEM format) |
| `/etc/ssh/ssh_known_hosts` | Decoy SSH known_hosts entry for internal jump host |
| `/root/.ssh/config` | SSH config with decoy `jump.corp-internal.local` and `bastion` hosts |
| `/root/.git-credentials` | GitHub and GitLab PAT credentials for `git credential store` |
| `/root/.gitconfig` | git config pointing credential helper to the decoy store |
| `/root/.kube/config` | Kubeconfig with decoy k8s service account JWT for `corp-cluster` |
| `/root/.docker/config.json` | Docker registry auth for `registry.hub.docker.com` and `ghcr.io` |
| `/root/.config/gcloud/application_default_credentials.json` | GCP service account JSON |
| `/opt/decoy/.env` | `API_KEY`, `DATABASE_URL`, `REDIS_URL`, `SECRET_KEY`, `JWT_SECRET` |
| `/opt/decoy/config.yaml` | Application config YAML with DB, AWS, and API key sections |
| `/opt/decoy/browser_passwords.csv` | Decoy browser-exported password CSV |
| `/opt/decoy/passwords.txt` | Decoy plaintext password list |
| `/opt/decoy/decoy_memory.py` | Decoy in-memory service (runs as systemd unit) |

User-level copies of AWS, SSH, and GCP credentials are also seeded under `/home/{{ ansible_user }}/`.

## Ansible variables

All token values are supplied by the ADG token engine at runtime. Override defaults by setting:

| Variable | Source | Example format |
|---|---|---|
| `adg_api_key` | token engine | `sk_live_...` |
| `adg_github_token` | token engine | `ghp_...` |
| `adg_gitlab_token` | token engine | `glpat-...` |
| `adg_aws_key_id` | token engine | `AKIA...` |
| `adg_aws_secret` | token engine | 40-char base64 |
| `adg_db_url` | token engine | `postgresql://user:pass@host/db` |
| `adg_k8s_token` | token engine | 3-part JWT |
| `adg_ssh_hostname` | token engine | `jump.corp-internal.local` |
| `adg_ssh_pubkey` | token engine | RSA public key blob |

## Playbooks

| Playbook | Purpose |
|---|---|
| `ansible/playbooks/deploy-linux.yaml` | Deploy all Linux breadcrumbs |
| `ansible/playbooks/deploy-windows.yaml` | Deploy all Windows breadcrumbs |
| `ansible/playbooks/rollback-linux.yaml` | Remove all Linux breadcrumbs cleanly |
| `ansible/playbooks/rollback-windows.yaml` | Remove all Windows breadcrumbs cleanly |

## Running

```bash
# Deploy to a host group defined in inventory
ansible-playbook -i inventory/hosts ansible/playbooks/deploy-linux.yaml \
  -e "adg_api_key=$(curl -s http://token-engine:8081/tokens -d '{"token_type":"api_key"}' | jq -r .value)"

# Roll back
ansible-playbook -i inventory/hosts ansible/playbooks/rollback-linux.yaml
```

## Decoy memory service

`scripts/decoy_memory.py` runs as a systemd service (`decoy-memory.service`) and keeps sensitive-looking strings in process memory. This causes the strings to appear in `/proc/<pid>/mem` dumps and in memory forensics captures — further increasing detection fidelity against attackers who enumerate running processes.
