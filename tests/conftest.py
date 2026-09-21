"""
SecureMailScope - Pytest shared fixtures.
Provides an authenticated FastAPI TestClient for tests that call protected API endpoints.
"""
import uuid
import pytest
from fastapi.testclient import TestClient
from securemailscope.api.app import app


def make_authed_client() -> TestClient:
    """
    Register a fresh test user via /api/auth/signup, return a TestClient
    whose default headers include the resulting Bearer token.
    This is a plain helper (not a fixture) so it can also be called from
    module-level setup in files that do not use pytest fixtures.
    """
    client = TestClient(app, raise_server_exceptions=True)
    # Each call creates a unique user so tests don't collide
    unique_tag = uuid.uuid4().hex[:8]
    email = f"testuser_{unique_tag}@securemailscope.test"
    password = "TestPass1234!"
    resp = client.post(
        "/api/auth/signup",
        json={"email": email, "password": password, "full_name": "Test Analyst"}
    )
    assert resp.status_code == 200, (
        f"Test auth setup failed: {resp.status_code} — {resp.text}"
    )
    token = resp.json().get("access_token") or resp.json().get("token")
    assert token, "Signup response missing token field"

    authed = TestClient(app, raise_server_exceptions=True,
                        headers={"Authorization": f"Bearer {token}"})
    return authed


@pytest.fixture()
def authed_client() -> TestClient:
    """Pytest fixture: authenticated TestClient for a fresh test user."""
    return make_authed_client()
