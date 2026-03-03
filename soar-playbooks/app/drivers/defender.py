import httpx


def isolate_device(api_url: str, token: str, device_id: str) -> None:
    headers = {"Authorization": f"Bearer {token}"}
    httpx.post(
        f"{api_url}/api/machines/{device_id}/isolate",
        headers=headers,
        json={"isolationType": "Full"},
        timeout=10,
    )
