from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    rules_path: str = "./rules/example.yaml"
    state_db_path: str = "./state/controller.db"
    state_db_url: str = "sqlite:///./state/controller.db"
    orchestration_mode: str = "dry-run"  # dry-run | kubernetes

    # DNS
    dns_api_url: str = "http://powerdns-api.local:8081"
    dns_api_key: str = ""
    dns_mode: str = "powerdns"  # powerdns | rfc2136 | route53 | cloudflare
    dns_rfc2136_server: str = ""
    dns_rfc2136_key_name: str = ""
    dns_rfc2136_key_secret: str = ""
    dns_route53_zone_id: str = ""
    dns_cloudflare_zone_id: str = ""
    dns_cloudflare_token: str = ""

    # SIEM — comma-separate multiple modes: "splunk,sentinel"
    alert_webhook_url: str = "http://siem-webhook.local/ingest"
    siem_mode: str = "webhook"
    siem_url: str = "http://siem-webhook.local/ingest"
    siem_token: str = ""
    siem_index: str = "main"
    siem_webhook_secret: str = ""
    # Sentinel
    siem_sentinel_workspace_id: str = ""
    siem_sentinel_shared_key: str = ""
    # Sumo Logic
    siem_sumologic_url: str = ""
    # Datadog
    siem_datadog_api_key: str = ""
    siem_datadog_site: str = "datadoghq.com"

    # Active Directory
    ad_server: str = ""
    ad_user: str = ""
    ad_password: str = ""
    ad_base_dn: str = ""

    # CMDB
    cmdb_url: str = ""
    cmdb_token: str = ""

    # Governance
    approvers: str = ""
    policy_path: str = "./policies/deception-policy.yaml"
    admin_ui_enabled: bool = True

    # Event bus
    bus_mode: str = "in-memory"  # in-memory | redis
    redis_url: str = "redis://localhost:6379/0"
    ttl_reap_interval: int = 30

    # Leader election
    leader_election: bool = False
    leader_lock_key: str = "adg-controller-leader"
    leader_lock_ttl: int = 20
    bus_queue_size: int = 1000

    # Auth
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    mtls_required: bool = True

    # Audit & observability
    audit_log_path: str = "./state/audit.log"
    action_audit_log_path: str = "./state/action_audit.log"
    rate_limit: str = "60/minute"
    otlp_endpoint: str = ""

    # Vault
    vault_addr: str = ""
    vault_token: str = ""
    vault_secret_path: str = ""

    # Enrichment
    abuseipdb_key: str = ""
    otx_key: str = ""
    enrichment_enabled: bool = True

    class Config:
        env_prefix = "ADG_"

