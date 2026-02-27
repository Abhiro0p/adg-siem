import json
from pathlib import Path

from faker import Faker

faker = Faker()


def main():
    base = Path("/data")
    base.mkdir(parents=True, exist_ok=True)
    users = [
        {"username": faker.user_name(), "email": faker.email(), "last_login": faker.iso8601()}
        for _ in range(50)
    ]
    secrets = [
        {"name": "backup_key", "value": faker.sha1()},
        {"name": "db_password", "value": faker.password(length=16)},
    ]
    (base / "users.json").write_text(json.dumps(users, indent=2))
    (base / "secrets.json").write_text(json.dumps(secrets, indent=2))


if __name__ == "__main__":
    main()
