import time

# Hold fake credentials in memory for dump-based discovery.
FAKE_SECRETS = [
    "DOMAIN\\svc_backup:Summer2026!",
    "DOMAIN\\svc_ci:Winter2026!",
    "KRBTGT:DecoyTicket-123456",
]

while True:
    time.sleep(60)
