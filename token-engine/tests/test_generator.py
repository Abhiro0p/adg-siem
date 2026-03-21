from app.generator import generate_token


def test_generate_ssh_key():
    token = generate_token("ssh_key", ttl_hours=1)
    assert token.token_type == "ssh_key"
    assert token.value.startswith("ssh-rsa ")


def test_generate_api_key():
    token = generate_token("env_api_key")
    # prefix is one of: sk_, pk_, api_, key_, tok_
    assert "_" in token.value
    assert len(token.value) > 10

