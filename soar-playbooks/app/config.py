from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    mtls_required: bool = True
    audit_log_path: str = "./state/audit.log"
    action_audit_log_path: str = "./state/action_audit.log"
    rate_limit: str = "60/minute"
    otlp_endpoint: str = ""

    # Vault
    vault_addr: str = ""
    vault_token: str = ""
    vault_secret_path: str = ""

    # EDR
    defender_url: str = ""
    defender_token: str = ""
    crowdstrike_url: str = ""
    crowdstrike_token: str = ""
    sentinelone_url: str = ""
    sentinelone_token: str = ""

    # NAC
    ise_url: str = ""
    ise_user: str = ""
    ise_password: str = ""

    # Notifications
    slack_webhook_url: str = ""
    pagerduty_routing_key: str = ""

    # Ticketing
    jira_url: str = ""
    jira_user: str = ""
    jira_token: str = ""
    jira_project: str = "SOC"

    # Active Directory (for account disable)
    ad_server: str = ""
    ad_user: str = ""
    ad_password: str = ""
    ad_base_dn: str = ""

    class Config:
        env_prefix = "ADG_SOAR_"

