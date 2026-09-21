import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from securemailscope.api.app import app
from securemailscope.core.security import verify_access_token
from securemailscope.db.models import AuthSessionModel, InvestigationModel, UserModel
from securemailscope.db.session import Base, SessionLocal, engine, init_db
from securemailscope.evidence.models import Investigation
from securemailscope.evidence.ledger import EvidenceLedger


def _client():
    init_db()
    return TestClient(app)


def _signup(client: TestClient, email: str):
    resp = client.post(
        "/api/auth/signup",
        json={"email": email, "password": "CorrectHorse123!", "full_name": email.split("@")[0]},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return data["user_id"], data["access_token"]


def _auth(token: str):
    return {"Authorization": f"Bearer {token}"}


def _email(label: str) -> str:
    return f"{label}-{uuid.uuid4().hex[:8]}@example.test"


def _create_db_investigation(inv_id: str, user_id: str, artifact_name: str = "owned.pcap"):
    ledger = EvidenceLedger.get_instance()
    inv_obj = Investigation(
        investigation_id=inv_id,
        user_id=user_id,
        artifact_name=artifact_name,
        artifact_path="/tmp/securemailscope-nonexistent.pcap",
        artifact_sha256="0" * 64,
        artifact_md5="0" * 32,
        artifact_size=1024,
        status="COMPLETED",
    )
    ledger.save_investigation(inv_obj)
    db = SessionLocal()
    try:
        inv = db.query(InvestigationModel).filter_by(investigation_id=inv_id).first()
        if inv:
            inv.user_id = user_id
            db.commit()
    finally:
        db.close()


def test_protected_investigation_routes_hide_cross_user_resources():
    client = _client()
    user_a, token_a = _signup(client, _email("idor-owner"))
    _user_b, token_b = _signup(client, _email("idor-attacker"))
    inv_id = f"INV-IDOR-{uuid.uuid4().hex[:8].upper()}"
    _create_db_investigation(inv_id, user_a)

    protected_paths = [
        ("GET", f"/api/investigations/{inv_id}"),
        ("GET", f"/api/investigations/{inv_id}/evidence"),
        ("GET", f"/api/investigations/{inv_id}/findings"),
        ("GET", f"/api/investigations/{inv_id}/timeline"),
        ("GET", f"/api/investigations/{inv_id}/sessions"),
        ("GET", f"/api/investigations/{inv_id}/replay"),
        ("GET", f"/api/investigations/{inv_id}/reports/json"),
        ("POST", f"/api/investigations/{inv_id}/analyze"),
        ("POST", f"/api/investigations/{inv_id}/agent/step"),
    ]

    unauth_client = TestClient(app)
    for method, path in protected_paths:
        json_body = {"tool_name": "pcap.completeness"} if path.endswith("/agent/step") else None
        unauth = unauth_client.request(method, path, json=json_body)
        assert unauth.status_code == 401, (method, path, unauth.status_code, unauth.text)

        cross_user = client.request(method, path, headers=_auth(token_b), json=json_body)
        assert cross_user.status_code == 404, (method, path, cross_user.status_code, cross_user.text)
        assert "owned.pcap" not in cross_user.text
        assert inv_id not in cross_user.text

    own = client.get(f"/api/investigations/{inv_id}", headers=_auth(token_a))
    assert own.status_code in (200, 404)
    if own.status_code == 404:
        assert "owned.pcap" not in own.text


def test_global_evidence_and_finding_routes_require_authentication():
    client = _client()
    _user_id, token = _signup(client, _email("global-authz"))
    unauth_client = TestClient(app)

    for path in ["/api/all-evidence", "/api/all-findings"]:
        assert unauth_client.get(path).status_code == 401
        resp = client.get(path, headers=_auth(token))
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)


def test_logout_revocation_is_database_backed_and_survives_new_session():
    client = _client()
    _user_id, token = _signup(client, _email("durable-session"))
    payload = verify_access_token(token)
    assert payload and payload.get("sid")

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    db = SessionLocal()
    try:
        row = db.query(AuthSessionModel).filter_by(session_id=payload["sid"], token_hash=token_hash).first()
        assert row is not None
        assert row.revoked_at is None
    finally:
        db.close()

    assert client.get("/api/auth/me", headers=_auth(token)).status_code == 200
    logout = client.post("/api/auth/logout", headers=_auth(token))
    assert logout.status_code == 200

    db = SessionLocal()
    try:
        row = db.query(AuthSessionModel).filter_by(session_id=payload["sid"], token_hash=token_hash).first()
        assert row is not None
        assert row.revoked_at is not None
    finally:
        db.close()

    assert client.get("/api/auth/me", headers=_auth(token)).status_code == 401


def test_expired_persisted_session_is_rejected():
    client = _client()
    _user_id, token = _signup(client, _email("expired-session"))
    payload = verify_access_token(token)
    assert payload and payload.get("sid")

    db = SessionLocal()
    try:
        row = db.query(AuthSessionModel).filter_by(session_id=payload["sid"]).first()
        assert row is not None
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    assert client.get("/api/auth/me", headers=_auth(token)).status_code == 401


def test_raw_bearer_token_never_stored_plaintext():
    """Verify raw bearer tokens are never stored in plaintext in the database."""
    client = _client()
    _user_id, token = _signup(client, _email("plaintext-check"))
    
    db = SessionLocal()
    try:
        # Check all sessions in the DB to ensure raw token is nowhere in the DB
        sessions = db.query(AuthSessionModel).all()
        assert len(sessions) > 0
        for s in sessions:
            assert s.token_hash != token
            assert token not in str(s.__dict__)
            # Ensure the hash is 64 hex chars (SHA-256)
            assert len(s.token_hash) == 64
            assert all(c in "0123456789abcdefABCDEF" for c in s.token_hash)
    finally:
        db.close()


def test_logout_revocation_survives_process_restart_simulation():
    """Verify logout revocation persists in DB and survives in-memory cache clear / restart simulation."""
    from securemailscope.core import security
    client = _client()
    _user_id, token = _signup(client, _email("restart-sim"))

    # Token works initially
    assert client.get("/api/auth/me", headers=_auth(token)).status_code == 200

    # User logs out
    resp = client.post("/api/auth/logout", headers=_auth(token))
    assert resp.status_code == 200

    # Simulate process restart by clearing the ephemeral in-memory revocation set
    security._REVOKED_TOKENS.clear()

    # Create a fresh TestClient and verify the token remains rejected strictly via DB check
    fresh_client = TestClient(app)
    unauth_resp = fresh_client.get("/api/auth/me", headers=_auth(token))
    assert unauth_resp.status_code == 401

    # Also verify on a protected investigation list route
    unauth_inv = fresh_client.get("/api/investigations", headers=_auth(token))
    assert unauth_inv.status_code == 401


def test_malformed_and_tampered_tokens_rejected():
    """Verify malformed, truncated, and tampered tokens are rejected with 401."""
    client = _client()
    _user_id, valid_token = _signup(client, _email("malformed-token"))

    bad_tokens = [
        "not-a-token",
        "header-only",
        "a.b.c",  # wrong segment count
        "invalid!base64.invalidsig",
        f"{valid_token}tampered",
        valid_token.rsplit(".", 1)[0] + ".tamperedsig",
        "",
    ]

    clean_client = TestClient(app)
    for bad in bad_tokens:
        resp = clean_client.get("/api/auth/me", headers={"Authorization": f"Bearer {bad}"} if bad else {})
        assert resp.status_code == 401, f"Expected 401 for token '{bad}', got {resp.status_code}"


def test_cross_user_reports_and_artifacts_prevented(tmp_path):
    """Verify User B cannot access User A's reports or upload artifacts to User A's investigation."""
    client = _client()
    user_a, token_a = _signup(client, _email("report-owner"))
    _user_b, token_b = _signup(client, _email("report-attacker"))

    inv_id = f"INV-REPORT-{uuid.uuid4().hex[:8].upper()}"
    _create_db_investigation(inv_id, user_a)

    # User B attempts to access reports of User A -> must return 404 (not found for User B)
    for report_format in ["json", "html", "pdf"]:
        resp = client.get(f"/api/investigations/{inv_id}/reports/{report_format}", headers=_auth(token_b))
        assert resp.status_code == 404, f"Expected 404 for report/{report_format}, got {resp.status_code}"

    # User B attempts to upload an artifact to User A's investigation -> must return 404
    dummy_pcap = tmp_path / "attack.pcap"
    dummy_pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16)
    with open(dummy_pcap, "rb") as f:
        resp = client.post(
            f"/api/investigations/{inv_id}/artifacts",
            headers=_auth(token_b),
            files={"file": ("attack.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    assert resp.status_code == 404, f"Expected 404 for artifact upload, got {resp.status_code}"


def test_cross_user_websocket_rejected():
    """Verify WebSocket rejects unauthenticated connections and cross-user investigation access."""
    client = _client()
    user_a, token_a = _signup(client, _email("ws-owner"))
    _user_b, token_b = _signup(client, _email("ws-attacker"))

    inv_id = f"INV-WS-{uuid.uuid4().hex[:8].upper()}"
    _create_db_investigation(inv_id, user_a)

    # 1. Unauthenticated WebSocket connection -> rejected
    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws/{inv_id}") as ws:
            pass

    # 2. Cross-user WebSocket connection (User B connecting to User A's investigation) -> rejected
    with pytest.raises(Exception):
        with client.websocket_connect(f"/ws/{inv_id}?token={token_b}") as ws:
            pass


def test_list_endpoints_strictly_isolate_user_data():
    """Verify list endpoints return strictly the authenticated user's data."""
    client = _client()
    user_a, token_a = _signup(client, _email("list-owner-a"))
    user_b, token_b = _signup(client, _email("list-owner-b"))

    inv_a = f"INV-A-{uuid.uuid4().hex[:8].upper()}"
    inv_b = f"INV-B-{uuid.uuid4().hex[:8].upper()}"
    _create_db_investigation(inv_a, user_a, "owner_a.pcap")
    _create_db_investigation(inv_b, user_b, "owner_b.pcap")

    # User A lists investigations
    resp_a = client.get("/api/investigations", headers=_auth(token_a))
    assert resp_a.status_code == 200
    ids_a = [item["investigation_id"] for item in resp_a.json()]
    assert inv_a in ids_a
    assert inv_b not in ids_a

    # User B lists investigations
    resp_b = client.get("/api/investigations", headers=_auth(token_b))
    assert resp_b.status_code == 200
    ids_b = [item["investigation_id"] for item in resp_b.json()]
    assert inv_b in ids_b
    assert inv_a not in ids_b

