from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    db_path: str = "./state/tokens.db"
    webhook_url: str = "http://siem-webhook.local/ingest"
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    mtls_required: bool = True
    audit_log_path: str = "./state/audit.log"
    rate_limit: str = "60/minute"
    otlp_endpoint: str = ""
    vault_addr: str = ""
    vault_token: str = ""
    vault_secret_path: str = ""

    class Config:
        env_prefix = "ADG_TOKEN_"

