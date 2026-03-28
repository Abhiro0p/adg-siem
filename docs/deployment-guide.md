# Deployment Guide

## Prerequisites

- Kubernetes cluster (k3s, EKS, GKE, or AKS)
- `kubectl` and `helm` installed and configured
- Container registry accessible from the cluster
- HashiCorp Vault or Kubernetes Secret management for credentials
- (Optional) Active Directory, PowerDNS/Route53/Cloudflare, SIEM, PagerDuty, Jira

## 1. Build container images

```bash
# Controller
docker build -t your-registry/adg-controller:latest controller/
docker push your-registry/adg-controller:latest

# Token engine
docker build -t your-registry/adg-token-engine:latest token-engine/
docker push your-registry/adg-token-engine:latest

# SOAR playbooks
docker build -t your-registry/adg-soar:latest soar-playbooks/
docker push your-registry/adg-soar:latest

# Honeypot apps
docker build -t your-registry/adg-fake-jenkins:latest honeypot-farm/apps/fake-jenkins/
docker build -t your-registry/adg-fake-grafana:latest honeypot-farm/apps/fake-grafana/
docker build -t your-registry/adg-fake-mysql:latest honeypot-farm/apps/fake-mysql/
docker build -t your-registry/adg-fake-smtp:latest honeypot-farm/apps/fake-smtp/
docker build -t your-registry/adg-fake-s3:latest honeypot-farm/apps/fake-s3/
```

## 2. Set up secrets

Create Kubernetes Secrets (or configure Vault) before applying manifests:

```bash
kubectl create secret generic adg-controller-secrets \
  --from-literal=ADG_JWT_SECRET=$(openssl rand -hex 32) \
  --from-literal=ADG_SIEM_TOKEN=your-splunk-token \
  --from-literal=ADG_ABUSEIPDB_KEY=your-key \
  --from-literal=ADG_OTX_KEY=your-key

kubectl create secret generic adg-soar-secrets \
  --from-literal=ADG_SOAR_JWT_SECRET=$(openssl rand -hex 32) \
  --from-literal=ADG_SOAR_SLACK_WEBHOOK_URL=https://hooks.slack.com/... \
  --from-literal=ADG_SOAR_PAGERDUTY_ROUTING_KEY=your-key
```

## 3. Deploy the event bus

```bash
kubectl apply -f infra/k8s/bus/kafka.yaml
kubectl apply -f infra/k8s/bus/redis.yaml

# For HA deployments:
kubectl apply -f infra/k8s/bus/kafka-ha.yaml
kubectl apply -f infra/k8s/bus/redis-ha.yaml
```

## 4. Deploy durable state (Postgres)

```bash
# Replace the placeholder password before applying
kubectl apply -f infra/k8s/storage/postgres-secret.yaml
kubectl apply -f infra/k8s/storage/postgres.yaml
```

## 5. Deploy the honeypot namespace

```bash
kubectl apply -f infra/k8s/honeypots/namespace.yaml
kubectl apply -f infra/k8s/honeypots/networkpolicy.yaml
```

The network policy denies all egress from the `honeypots` namespace except to the controller webhook. This prevents attacker tooling from making outbound connections if a honeypot pod is compromised.

## 6. Deploy core services

```bash
kubectl apply -f infra/k8s/honeypots/controller.yaml
kubectl apply -f infra/k8s/token-engine.yaml
kubectl apply -f infra/k8s/soar.yaml
```

Verify liveness and readiness:

```bash
kubectl rollout status deployment/adg-controller -n honeypots
kubectl get pods -n honeypots
curl http://<controller-ip>:8080/health/live
curl http://<controller-ip>:8080/health/ready
```

## 7. Deploy honeypots

```bash
kubectl apply -f infra/k8s/honeypots/cowrie.yaml
kubectl apply -f infra/k8s/honeypots/dionaea.yaml
kubectl apply -f infra/k8s/honeypots/pyrdp.yaml
kubectl apply -f infra/k8s/honeypots/fake-jenkins.yaml
kubectl apply -f infra/k8s/honeypots/fake-grafana.yaml
```

Each manifest includes a `pcap` sidecar (tcpdump) and a `pcap-forwarder` sidecar that ships PCAPs to Kafka.

## 8. Deploy autoscaling

```bash
kubectl apply -f infra/k8s/honeypots/controller-hpa.yaml
kubectl apply -f infra/k8s/token-engine-hpa.yaml
kubectl apply -f infra/k8s/soar-hpa.yaml
```

## 9. Set up retention CronJobs

```bash
kubectl apply -f infra/k8s/retention/log-retention.yaml   # 14-day audit log retention
kubectl apply -f infra/k8s/retention/pcap-retention.yaml   # 7-day PCAP retention
kubectl apply -f infra/k8s/token-rotation.yaml              # periodic honeytoken rotation
```

## 10. Deploy breadcrumbs

Generate tokens from the token engine and deploy to endpoints:

```bash
# Fetch token values from token engine
API_KEY=$(curl -s -X POST http://token-engine:8081/tokens \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"token_type":"api_key"}' | jq -r .value)

# Deploy breadcrumbs
ansible-playbook -i inventory/hosts \
  breadcrumbs/ansible/playbooks/deploy-linux.yaml \
  -e "adg_api_key=${API_KEY}"
```

## Helm deployment (alternative)

```bash
helm upgrade --install adg-controller charts/adg-controller \
  --set image.repository=your-registry/adg-controller \
  --set image.tag=latest \
  --set env.ADG_SIEM_MODE=webhook,splunk \
  --set secrets.jwtSecret=your-secret

helm upgrade --install adg-token-engine charts/token-engine \
  --set image.repository=your-registry/adg-token-engine

helm upgrade --install adg-soar charts/soar-playbooks \
  --set image.repository=your-registry/adg-soar

helm upgrade --install adg-honeypots charts/honeypots \
  --set fakeJenkins.image=your-registry/adg-fake-jenkins \
  --set fakeGrafana.image=your-registry/adg-fake-grafana
```

## Vault integration

If using HashiCorp Vault, configure the Vault address and token before starting services:

```bash
# Write secrets to Vault
vault kv put secret/adg/controller \
  jwt_secret="$(openssl rand -hex 32)" \
  abuseipdb_key="your-key" \
  otx_key="your-key" \
  siem_token="your-splunk-token"
```

Set `ADG_VAULT_ADDR`, `ADG_VAULT_TOKEN`, and `ADG_VAULT_SECRET_PATH` on each service. Vault values override environment variables of the same name.

## Observability

```bash
# Prometheus scrape targets — each service exposes /metrics
# Add to your prometheus.yml:
#   - job_name: adg
#     static_configs:
#       - targets: ['controller:8080', 'token-engine:8081', 'soar:8090']

# OpenTelemetry — set on each service:
# ADG_OTLP_ENDPOINT=http://otel-collector:4317
```

## Smoke test

```bash
# Ingest a test event
curl -X POST http://controller:8080/events \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "port_scan",
    "src_ip": "10.0.1.50",
    "dst_port": 22,
    "protocol": "tcp",
    "timestamp": "2025-01-01T00:00:00Z"
  }'

# Check lures were deployed
curl http://controller:8080/lures -H "Authorization: Bearer $JWT"

# Check coverage
curl http://controller:8080/coverage -H "Authorization: Bearer $JWT"
```
