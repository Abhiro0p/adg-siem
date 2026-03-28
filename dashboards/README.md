# Dashboards

Grafana and Kibana dashboard definitions for ADG visibility.

## Contents

| File | Tool | Purpose |
|---|---|---|
| `grafana/deception-overview.json` | Grafana | Real-time coverage, alert rate, active lures, bus backlog |
| `kibana/deception.ndjson` | Kibana | Alert timeline, MITRE ATT&CK heatmap, enrichment breakdown |

## Grafana dashboard panels

Import `grafana/deception-overview.json` into your Grafana instance (Settings → Import).

**Row: Coverage**
- Active lures by type (bar chart, `adg_lures_active_total` gauge)
- Coverage heatmap by subnet (stat panel, calls `/coverage`)
- Lures deployed over time (time series)

**Row: Alerts**
- Alert rate (events/minute, `adg_alerts_emitted_total[1m]`)
- Alert severity breakdown (pie chart)
- Kill-chain stage distribution (horizontal bar: reconnaissance → exploitation → objectives)
- MITRE technique frequency (table: technique ID, count, last seen)

**Row: Enrichment**
- Top source countries (world map, GeoIP data)
- Top AbuseIPDB confidence scores (histogram)
- OTX pulse count distribution (histogram)

**Row: Infrastructure**
- Event bus queue depth (`adg_bus_queue_depth`)
- HTTP request latency p95 (`http_request_duration_seconds`)
- Service error rate (`http_requests_total{status="5xx"}`)
- Honeytoken access events over time

## Kibana dashboard

Import `kibana/deception.ndjson` via Stack Management → Saved Objects → Import.

**Visualisations**:
- Alert timeline (area chart by severity)
- MITRE ATT&CK matrix (heat map — tactic × technique)
- Source IP map (coordinate map with AbuseIPDB confidence overlay)
- Top triggered rules (data table)
- SOAR action outcomes (pie chart: success/failure per action type)
- Request ID correlation trace (discover saved search)

## Data sources

| Grafana data source | URL | Notes |
|---|---|---|
| Prometheus | `http://prometheus:9090` | Metrics from all services |
| Elasticsearch | `http://elasticsearch:9200` | Alert and audit log index |

| Kibana index pattern | Index | Notes |
|---|---|---|
| `adg-alerts-*` | SIEM alert index | One document per alert |
| `adg-audit-*` | Audit log index | One document per action |

## Alerting rules (Grafana)

Recommended alert rules to configure in Grafana Alerting:

| Alert | Condition | Severity |
|---|---|---|
| Bus backlog | `adg_bus_queue_depth > 800` for 5m | Warning |
| High error rate | `rate(http_requests_total{status="5xx"}[5m]) > 0.01` | Critical |
| No events processed | `increase(adg_rules_evaluated_total[15m]) == 0` | Warning |
| Redis stream lag | `XPENDING adg-events > 1000` | Warning |
| Lures below threshold | `adg_lures_active_total < 3` | Info |
