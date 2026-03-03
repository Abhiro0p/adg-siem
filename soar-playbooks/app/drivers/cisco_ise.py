import httpx


def quarantine_mac(api_url: str, username: str, password: str, mac: str) -> None:
    httpx.post(
        f"{api_url}/ers/config/endpoint",
        auth=(username, password),
        json={"ERSEndPoint": {"mac": mac, "groupId": "Quarantined"}},
        timeout=10,
    )
