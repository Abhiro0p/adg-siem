from __future__ import annotations

import json
from typing import Any, Dict

from faker import Faker

from .generator import generate_token

faker = Faker()


def build_decoy_bundle() -> Dict[str, str]:
    """
    Returns a mapping of filename → file content for all decoy artifact types.
    This bundle can be staged on an endpoint via Ansible to function as breadcrumbs.
    """
    aws_token = generate_token("aws_key")
    gcp_token = generate_token("gcp_key")
    azure_token = generate_token("azure_key")
    ssh_token = generate_token("ssh_key")
    api_token = generate_token("env_api_key")
    pw_token = generate_token("browser_password")
    k8s_token = generate_token("k8s_token")
    git_cred = generate_token("git_credential")
    docker_cfg = generate_token("docker_config")
    db_conn = generate_token("db_connection_string")
    aws_cli = generate_token("aws_cli_config")
    gh_pat = generate_token("github_pat")

    user = faker.user_name()
    domain = faker.domain_name()

    bundle: Dict[str, str] = {
        # AWS credentials file
        "aws_credentials": aws_cli.value,
        # GCP service account JSON
        "gcp_service_account.json": gcp_token.value,
        # Azure service principal JSON
        "azure_credentials.json": azure_token.value,
        # SSH private key placeholder
        "id_rsa_decoy": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            + ssh_token.value.split(" ")[1][:64] + "\n"
            + "-----END RSA PRIVATE KEY-----\n"
        ),
        # SSH known_hosts
        "known_hosts": f"{domain} {ssh_token.value}\n",
        # Environment file
        ".env": (
            f"API_KEY={api_token.value}\n"
            f"GITHUB_TOKEN={gh_pat.value}\n"
            f"DATABASE_URL={db_conn.value}\n"
        ),
        # Passwords file
        "passwords.txt": (
            f"admin:{pw_token.value}\n"
            f"{user}:{faker.password(length=14)}\n"
            f"root:{faker.password(length=12)}\n"
        ),
        # Application config
        "config.yaml": (
            f"api_key: {api_token.value}\n"
            f"db_url: {db_conn.value}\n"
            f"aws_access_key_id: {aws_token.value}\n"
        ),
        # Docker auth
        ".docker/config.json": docker_cfg.value,
        # Kubernetes service account token
        "k8s_token": k8s_token.value,
        # Git credentials
        ".git-credentials": git_cred.value + "\n",
        # SSH config with decoy host
        ".ssh/config": (
            f"Host {domain}\n"
            f"  HostName {domain}\n"
            f"  User {user}\n"
            f"  IdentityFile ~/.ssh/id_rsa_decoy\n"
        ),
    }
    return bundle
