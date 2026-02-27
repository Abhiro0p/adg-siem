# Synthetic Data

Realistic fake users, files, and credentials mounted into honeypots to increase interaction depth and realism. Attackers who enumerate honeypot filesystems or user databases find plausible data, reducing the chance of premature detection abandonment.

## Contents

| File / directory | Purpose |
|---|---|
| `users.json` | Fake user accounts with realistic names, roles, and hashed passwords |
| `files/` | Decoy documents: financial reports, HR data, config files, source code snippets |
| `ssh_keys/` | Decoy SSH key pairs (public keys only, for `authorized_keys`) |
| `browser_passwords.csv` | Browser-exported password CSV (Cowrie file system) |
| `web_history.json` | Plausible browser history for web-app honeypots |
| `aws_profiles.ini` | Decoy AWS CLI credential profiles |

## Generating data

```bash
python scripts/seed_data.py \
  --users 50 \
  --files 100 \
  --output honeypot-farm/data/
```

Options:
- `--users N` — generate N fake user accounts
- `--files N` — generate N fake documents in `files/`
- `--seed SEED` — deterministic seed for reproducible output
- `--locale en_US` — Faker locale for names and addresses

## Mounting into honeypots

Synthetic data is mounted as a Kubernetes `ConfigMap` or `Secret` volume into honeypot pods. The PCAP sidecar also reads this data to seed memory with realistic strings that appear in memory forensics captures.

Example mount in a honeypot manifest:

```yaml
volumeMounts:
  - name: decoy-data
    mountPath: /home/user
volumes:
  - name: decoy-data
    configMap:
      name: honeypot-decoy-data
```

## Keeping data fresh

Regenerate synthetic data monthly to prevent fingerprinting. Commit the new output and roll the honeypot deployments:

```bash
python scripts/seed_data.py --seed $(date +%Y%m)
kubectl create configmap honeypot-decoy-data \
  --from-file=honeypot-farm/data/ \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment --selector=app.kubernetes.io/part-of=adg-honeypots -n honeypots
```
