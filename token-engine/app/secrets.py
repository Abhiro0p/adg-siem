from __future__ import annotations

from typing import Dict

import hvac

from .config import Settings


def load_vault_secrets(settings: Settings) -> Dict[str, str]:
    if not settings.vault_addr or not settings.vault_token or not settings.vault_secret_path:
        return {}
    client = hvac.Client(url=settings.vault_addr, token=settings.vault_token)
    secret = client.secrets.kv.v2.read_secret_version(path=settings.vault_secret_path)
    data = secret.get("data", {}).get("data", {})
    return {str(key): str(value) for key, value in data.items()}
