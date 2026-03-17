from datetime import datetime, timezone

from app.models import LureDeployment
from app.state import StateStore


def test_state_store_sqlite(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'state.db'}"
    store = StateStore(db_url)
    lure = LureDeployment(
        lure_id="1",
        lure_type="cowrie",
        subnet="10.0.0.0/24",
        hostname="cowrie-1",
        created_at=datetime.now(timezone.utc),
        ttl_seconds=10,
        metadata={},
    )
    store.add_lure(lure)
    assert len(store.list_lures()) == 1
    store.remove_lure("1")
    assert store.list_lures() == []
