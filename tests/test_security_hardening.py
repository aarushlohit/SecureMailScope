"""Security regression tests for secrets and session-token signing."""

from securemailscope.core import security


def test_missing_signing_secret_uses_ephemeral_random_key(monkeypatch):
    """A missing environment secret must never fall back to a public default."""
    monkeypatch.setattr(security.config, "secret_key", None)
    first = security._get_signing_secret()
    second = security._get_signing_secret()

    assert first == second
    assert first != b"securemailscope-insecure-dev-secret-key-change-in-prod"
    assert len(first) >= 32
