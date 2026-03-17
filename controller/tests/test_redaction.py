from app.redaction import redact_dict


def test_redacts_known_field_names():
    result = redact_dict({"password": "s3cr3t", "username": "admin"})
    assert result["password"] == "[REDACTED]"
    assert result["username"] == "admin"


def test_redacts_nested_dicts():
    result = redact_dict({"outer": {"token": "abc123", "name": "test"}})
    assert result["outer"]["token"] == "[REDACTED]"
    assert result["outer"]["name"] == "test"


def test_redacts_aws_key_value():
    result = redact_dict({"key": "AKIAIOSFODNN7EXAMPLE1234"})
    assert result["key"] == "[REDACTED]"


def test_redacts_jwt_in_value():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    result = redact_dict({"authorization": jwt})
    assert result["authorization"] == "[REDACTED]"


def test_redacts_list_values():
    result = redact_dict({"items": ["safe", "AKIAIOSFODNN7EXAMPLE1234"]})
    assert result["items"][0] == "safe"
    assert result["items"][1] == "[REDACTED]"


def test_extra_fields():
    result = redact_dict({"my_custom_secret": "val"}, extra_fields=["my_custom_secret"])
    assert result["my_custom_secret"] == "[REDACTED]"


def test_non_sensitive_unchanged():
    result = redact_dict({"src_ip": "10.0.0.1", "port": 22, "event_type": "scan"})
    assert result == {"src_ip": "10.0.0.1", "port": 22, "event_type": "scan"}
