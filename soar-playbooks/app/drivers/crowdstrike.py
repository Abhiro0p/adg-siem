import httpx


def isolate_device(api_url: str, token: str, device_id: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    httpx.post(
        f"{api_url}/devices/entities/devices-actions/v2?action_name=contain",
        headers=headers,
        json={"ids": [device_id]},
        timeout=10,
    )
