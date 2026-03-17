from app.decoy_files import build_decoy_bundle


def test_bundle_contains_files():
    bundle = build_decoy_bundle()
    assert "passwords.txt" in bundle
    assert "config.yaml" in bundle
