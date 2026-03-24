import httpx


def main():
    payload = {
        "source": "zeek",
        "event_type": "port_scan",
        "data": {"port": 8080, "src_ip": "10.10.20.50"},
    }
    httpx.post("http://localhost:8080/events", json=payload, timeout=5)


if __name__ == "__main__":
    main()
