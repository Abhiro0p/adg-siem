from app.rotator import rotate_tokens
from app.store import TokenStore


def test_rotate_tokens(tmp_path):
    store = TokenStore(str(tmp_path / "tokens.db"))
    tokens = rotate_tokens(store, ["ssh_key", "env_api_key"], ttl_hours=1)
    assert len(tokens) == 2
    assert len(store.list_tokens()) == 2
