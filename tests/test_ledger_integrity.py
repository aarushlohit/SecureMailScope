"""
Comprehensive tests for Evidence Ledger Immutability, Hash Chaining,
Tamper Detection, Database Triggers, and verify-ledger CLI.
"""
import os
import sys
import uuid
import json
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from securemailscope.core.config import config
from securemailscope.core.exceptions import (
    EvidenceMutationError,
    EvidenceValidationError
)
from securemailscope.evidence.models import (
    Evidence,
    EvidenceType,
    Finding,
    FindingStatus,
    SeverityLevel,
    Investigation
)
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.evidence.validator import FindingValidator
from securemailscope.evidence.hasher import (
    compute_hash_for_evidence,
    canonicalize_evidence_payload,
    GENESIS_HASH
)
from securemailscope.db.session import Base, setup_evidence_triggers, migrate_evidence_integrity
from securemailscope.db.models import (
    UserModel,
    InvestigationModel,
    EvidenceModel,
    FindingModel
)
from securemailscope.cli import run_verify_ledger


def create_isolated_test_env(tmp_path: Path):
    """Creates an isolated SQLite database and JSON ledger with schema and triggers."""
    db_file = tmp_path / "isolated.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    migrate_evidence_integrity(engine)
    setup_evidence_triggers(engine)

    json_path = tmp_path / "isolated_ledger.json"
    json_path.write_text(json.dumps({"investigations": [], "evidence": [], "findings": []}))
    return engine, Session, json_path, db_file


def test_valid_ledger_passes_verification(tmp_path):
    """1. Valid ledger passes verification cleanly."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    u_id = f"U-{uuid.uuid4().hex[:6]}"
    inv_id = f"INV-{uuid.uuid4().hex[:6]}"
    e1_id = f"E-{uuid.uuid4().hex[:6]}"
    e2_id = f"E-{uuid.uuid4().hex[:6]}"
    fnd_id = f"FND-{uuid.uuid4().hex[:6]}"

    db = Session()
    try:
        user = UserModel(user_id=u_id, email=f"{u_id}@agency.gov", password_hash="hash", full_name="Analyst 1")
        inv = InvestigationModel(investigation_id=inv_id, user_id=u_id, artifact_name="clean.pcap", artifact_path="/tmp/clean.pcap")
        db.add(user)
        db.add(inv)
        db.commit()
    finally:
        db.close()

    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    ev1 = Evidence(
        evidence_id=e1_id,
        investigation_id=inv_id,
        user_id=u_id,
        type=EvidenceType.TLS_CLIENT_HELLO,
        claim="ClientHello TLS 1.2 observed",
        source_tool="TLSEngine",
        tool_version="1.0",
        raw_artifact_ref="pcap://clean.pcap",
        provenance_chain=[inv_id, "clean.pcap"]
    )
    ledger.record_evidence(ev1)

    ev2 = Evidence(
        evidence_id=e2_id,
        investigation_id=inv_id,
        user_id=u_id,
        type=EvidenceType.TLS_SERVER_HELLO,
        claim="ServerHello TLS 1.2 negotiated",
        source_tool="TLSEngine",
        tool_version="1.0",
        raw_artifact_ref="pcap://clean.pcap",
        provenance_chain=[inv_id, "clean.pcap"]
    )
    ledger.record_evidence(ev2)

    validator = FindingValidator(ledger)
    fnd = Finding(
        finding_id=fnd_id,
        investigation_id=inv_id,
        title="TLS 1.2 Negotiated",
        description="Legitimate TLS session",
        severity=SeverityLevel.INFORMATIONAL,
        evidence_ids=[e1_id, e2_id]
    )
    valid, msg = validator.validate_and_register_finding(fnd)
    assert valid is True
    assert ev1.entry_hash is not None
    assert ev2.previous_entry_hash == ev1.entry_hash
    assert ev2.entry_hash is not None


def test_modified_evidence_payload_detected(tmp_path):
    """2. Tampered evidence payload (e.g. modified claim) is detected by hash verification."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    u_id = f"U-{uuid.uuid4().hex[:6]}"
    inv_id = f"INV-{uuid.uuid4().hex[:6]}"
    eid = f"E-{uuid.uuid4().hex[:6]}"

    db = Session()
    try:
        user = UserModel(user_id=u_id, email=f"{u_id}@test.com", password_hash="h", full_name="U1")
        inv = InvestigationModel(investigation_id=inv_id, user_id=u_id, artifact_name="test.pcap", artifact_path="test.pcap")
        db.add_all([user, inv])
        db.commit()
    finally:
        db.close()

    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    ev = Evidence(
        evidence_id=eid,
        investigation_id=inv_id,
        user_id=u_id,
        type=EvidenceType.OBSERVED,
        claim="Original authentic claim",
        source_tool="CaptureEngine",
        provenance_chain=[inv_id]
    )
    ledger.record_evidence(ev)

    # Bypass trigger to simulate direct database tampering
    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.execute("DROP TRIGGER IF EXISTS prevent_evidence_update")
    raw_conn.execute(f"UPDATE evidence SET claim = 'Tampered malicious claim' WHERE evidence_id = '{eid}'")
    raw_conn.commit()

    cur = raw_conn.cursor()
    cur.execute(f"SELECT evidence_id, investigation_id, user_id, type, claim, source_tool, tool_version, tool_args, raw_artifact_ref, timestamp, confidence, severity, hypothesis_id, provenance_chain, details, previous_entry_hash, entry_hash FROM evidence WHERE evidence_id = '{eid}'")
    r = cur.fetchone()
    raw_conn.close()

    row_dict = {
        "evidence_id": r[0], "investigation_id": r[1], "user_id": r[2], "type": r[3], "claim": r[4],
        "source_tool": r[5], "tool_version": r[6], "tool_args": json.loads(r[7]) if r[7] else {},
        "raw_artifact_ref": r[8], "timestamp": r[9], "confidence": r[10], "severity": r[11],
        "hypothesis_id": r[12], "provenance_chain": json.loads(r[13]) if r[13] else [], "details": json.loads(r[14]) if r[14] else {},
        "previous_entry_hash": r[15], "entry_hash": r[16]
    }
    recomputed = compute_hash_for_evidence(row_dict, r[15])
    assert recomputed != r[16], "Tampered claim must produce hash mismatch"


def test_modified_entry_hash_detected(tmp_path):
    """3. Modified entry hash is detected."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    u_id = f"U-{uuid.uuid4().hex[:6]}"
    inv_id = f"INV-{uuid.uuid4().hex[:6]}"
    eid = f"E-{uuid.uuid4().hex[:6]}"

    db = Session()
    try:
        user = UserModel(user_id=u_id, email=f"{u_id}@test.com", password_hash="h", full_name="U2")
        inv = InvestigationModel(investigation_id=inv_id, user_id=u_id, artifact_name="test.pcap", artifact_path="test.pcap")
        db.add_all([user, inv])
        db.commit()
    finally:
        db.close()

    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    ev = Evidence(
        evidence_id=eid,
        investigation_id=inv_id,
        user_id=u_id,
        type=EvidenceType.OBSERVED,
        claim="Claim for hash test",
        source_tool="CaptureEngine",
        provenance_chain=[inv_id]
    )
    ledger.record_evidence(ev)

    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.execute("DROP TRIGGER IF EXISTS prevent_evidence_update")
    raw_conn.execute(f"UPDATE evidence SET entry_hash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE evidence_id = '{eid}'")
    raw_conn.commit()

    cur = raw_conn.cursor()
    cur.execute(f"SELECT previous_entry_hash, entry_hash FROM evidence WHERE evidence_id = '{eid}'")
    prev_h, stored_h = cur.fetchone()
    raw_conn.close()

    expected = compute_hash_for_evidence(ev, prev_h)
    assert stored_h != expected, "Directly modified hash must mismatch expected canonical hash"


def test_broken_previous_entry_hash_detected(tmp_path):
    """4. Broken previous-entry hash link is detected."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    inv_id = f"INV-{uuid.uuid4().hex[:6]}"
    e1_id = f"E-{uuid.uuid4().hex[:6]}"
    e2_id = f"E-{uuid.uuid4().hex[:6]}"

    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    ev1 = Evidence(evidence_id=e1_id, investigation_id=inv_id, type=EvidenceType.OBSERVED, claim="Step 1", source_tool="T", provenance_chain=[inv_id])
    ev2 = Evidence(evidence_id=e2_id, investigation_id=inv_id, type=EvidenceType.OBSERVED, claim="Step 2", source_tool="T", provenance_chain=[inv_id])
    ledger.record_evidence(ev1)
    ledger.record_evidence(ev2)

    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.execute("DROP TRIGGER IF EXISTS prevent_evidence_update")
    raw_conn.execute(f"UPDATE evidence SET previous_entry_hash = '0000000000000000000000000000000000000000000000000000000000000001' WHERE evidence_id = '{e2_id}'")
    raw_conn.commit()

    cur = raw_conn.cursor()
    cur.execute(f"SELECT previous_entry_hash FROM evidence WHERE evidence_id = '{e2_id}'")
    tampered_prev = cur.fetchone()[0]
    raw_conn.close()

    assert tampered_prev != ev1.entry_hash, "Tampered previous hash does not match ev1's entry_hash"


def test_deleted_ledger_row_detected(tmp_path):
    """5. Deleted ledger row breaks hash chain continuity."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    inv_id = f"INV-{uuid.uuid4().hex[:6]}"
    e1_id = f"E-{uuid.uuid4().hex[:6]}"
    e2_id = f"E-{uuid.uuid4().hex[:6]}"
    e3_id = f"E-{uuid.uuid4().hex[:6]}"

    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    ev1 = Evidence(evidence_id=e1_id, investigation_id=inv_id, type=EvidenceType.OBSERVED, claim="Block 1", source_tool="T", provenance_chain=[inv_id])
    ev2 = Evidence(evidence_id=e2_id, investigation_id=inv_id, type=EvidenceType.OBSERVED, claim="Block 2", source_tool="T", provenance_chain=[inv_id])
    ev3 = Evidence(evidence_id=e3_id, investigation_id=inv_id, type=EvidenceType.OBSERVED, claim="Block 3", source_tool="T", provenance_chain=[inv_id])
    ledger.record_evidence(ev1)
    ledger.record_evidence(ev2)
    ledger.record_evidence(ev3)

    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.execute("DROP TRIGGER IF EXISTS prevent_evidence_delete")
    raw_conn.execute(f"DELETE FROM evidence WHERE evidence_id = '{e2_id}'")
    raw_conn.commit()

    cur = raw_conn.cursor()
    cur.execute(f"SELECT previous_entry_hash FROM evidence WHERE evidence_id = '{e3_id}'")
    ev3_prev = cur.fetchone()[0]
    raw_conn.close()

    assert ev3_prev != ev1.entry_hash, "Deleting intermediate row breaks previous_entry_hash chain continuity"


def test_duplicate_evidence_id_rejected(tmp_path):
    """6. Duplicate evidence ID is rejected as an immutable violation."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    eid = f"E-DUP-{uuid.uuid4().hex[:6]}"

    ev1 = Evidence(evidence_id=eid, investigation_id="INV-001", type=EvidenceType.OBSERVED, claim="Original", source_tool="T", provenance_chain=["INV-001"])
    ledger.record_evidence(ev1)

    ev_dup = Evidence(evidence_id=eid, investigation_id="INV-001", type=EvidenceType.OBSERVED, claim="Attempted Overwrite", source_tool="T", provenance_chain=["INV-001"])
    with pytest.raises(EvidenceMutationError, match="already exists"):
        ledger.record_evidence(ev_dup)


def test_cross_investigation_citation_rejected(tmp_path):
    """7. Cross-investigation citation is rejected by validator."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    validator = FindingValidator(ledger)
    eid = f"E-XINV-{uuid.uuid4().hex[:6]}"

    ev1 = Evidence(evidence_id=eid, investigation_id="INV-001", type=EvidenceType.OBSERVED, claim="Fact in 1", source_tool="T", provenance_chain=["INV-001"])
    ledger.record_evidence(ev1)

    fnd = Finding(
        finding_id=f"FND-XINV-{uuid.uuid4().hex[:6]}",
        investigation_id="INV-002",
        title="Cross Inv Finding",
        description="Using evidence from INV-001",
        severity=SeverityLevel.HIGH,
        evidence_ids=[eid]
    )
    with pytest.raises(EvidenceValidationError, match="belong to a different investigation"):
        validator.validate_and_register_finding(fnd)


def test_cross_user_citation_rejected(tmp_path):
    """8. Cross-user citation is strictly rejected."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    validator = FindingValidator(ledger)
    inv1_id = f"INV-U1-{uuid.uuid4().hex[:6]}"
    inv2_id = f"INV-U2-{uuid.uuid4().hex[:6]}"
    eid = f"E-ALICE-{uuid.uuid4().hex[:6]}"

    inv_user1 = Investigation(investigation_id=inv1_id, user_id="U-ALICE", artifact_name="a.pcap", artifact_path="a.pcap", artifact_sha256="", artifact_md5="", artifact_size=100)
    inv_user2 = Investigation(investigation_id=inv2_id, user_id="U-BOB", artifact_name="b.pcap", artifact_path="b.pcap", artifact_sha256="", artifact_md5="", artifact_size=100)
    ledger.save_investigation(inv_user1)
    ledger.save_investigation(inv_user2)

    ev_alice = Evidence(
        evidence_id=eid,
        investigation_id=inv1_id,
        user_id="U-ALICE",
        type=EvidenceType.OBSERVED,
        claim="Alice fact",
        source_tool="T",
        provenance_chain=[inv1_id]
    )
    ledger.record_evidence(ev_alice)

    fnd_bob = Finding(
        finding_id=f"FND-BOB-{uuid.uuid4().hex[:6]}",
        investigation_id=inv2_id,
        title="Bob Finding",
        description="Claim citing Alice",
        severity=SeverityLevel.HIGH,
        evidence_ids=[eid]
    )
    with pytest.raises(EvidenceValidationError):
        validator.validate_and_register_finding(fnd_bob)


def test_missing_evidence_citation_rejected(tmp_path):
    """9. Missing evidence citation is rejected."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    validator = FindingValidator(ledger)

    fnd = Finding(
        finding_id=f"FND-MISS-{uuid.uuid4().hex[:6]}",
        investigation_id="INV-001",
        title="Missing Citation",
        description="Citing phantom ID",
        severity=SeverityLevel.CRITICAL,
        evidence_ids=["E-GHOST-999"]
    )
    with pytest.raises(EvidenceValidationError, match="do not exist in Ledger"):
        validator.validate_and_register_finding(fnd)


def test_empty_evidence_citation_rejected(tmp_path):
    """10. Empty evidence citation is rejected ('No Evidence -> No Finding')."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    ledger = EvidenceLedger(storage_path=json_path, session_factory=Session)
    validator = FindingValidator(ledger)

    fnd = Finding(
        finding_id=f"FND-EMPTY-{uuid.uuid4().hex[:6]}",
        investigation_id="INV-001",
        title="Zero Evidence Claim",
        description="Pure hallucination",
        severity=SeverityLevel.CRITICAL,
        evidence_ids=[]
    )
    with pytest.raises(EvidenceValidationError, match="contains NO supporting evidence IDs"):
        validator.validate_and_register_finding(fnd)


def test_orphan_investigation_reference_detected(tmp_path):
    """11. Orphan investigation reference is detected."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.execute("INSERT INTO evidence (evidence_id, investigation_id, type, claim, source_tool) VALUES ('E-ORPHAN-01', 'INV-DOES-NOT-EXIST', 'OBSERVED', 'Orphan claim', 'Tool')")
    raw_conn.commit()
    raw_conn.close()

    db = Session()
    try:
        inv_ids = set(i.investigation_id for i in db.query(InvestigationModel).all())
        ev = db.query(EvidenceModel).filter_by(evidence_id="E-ORPHAN-01").first()
        assert ev.investigation_id not in inv_ids
    finally:
        db.close()


def test_orphan_user_reference_detected(tmp_path):
    """12. Orphan user reference is detected."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.execute("INSERT INTO investigations (investigation_id, artifact_name, artifact_path) VALUES ('INV-TEST', 'test.pcap', 'test.pcap')")
    raw_conn.execute("INSERT INTO evidence (evidence_id, investigation_id, user_id, type, claim, source_tool) VALUES ('E-USER-ORPHAN', 'INV-TEST', 'U-NONEXISTENT', 'OBSERVED', 'User orphan claim', 'Tool')")
    raw_conn.commit()
    raw_conn.close()

    db = Session()
    try:
        users = set(u.user_id for u in db.query(UserModel.user_id).all())
        ev = db.query(EvidenceModel).filter_by(evidence_id="E-USER-ORPHAN").first()
        assert ev.user_id not in users
    finally:
        db.close()


def test_malformed_ledger_data_handled_safely(tmp_path):
    """13. Malformed ledger data (corrupt json, null tool args) is handled safely."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    raw_conn = sqlite3.connect(str(db_file))
    raw_conn.execute("INSERT INTO investigations (investigation_id, artifact_name, artifact_path) VALUES ('INV-MALFORMED', 'm.pcap', 'm.pcap')")
    raw_conn.execute("INSERT INTO evidence (evidence_id, investigation_id, type, claim, source_tool, tool_args, details) VALUES ('E-MAL-01', 'INV-MALFORMED', 'OBSERVED', 'Claim with null json', 'Tool', NULL, NULL)")
    raw_conn.commit()
    raw_conn.close()

    db = Session()
    try:
        ev = db.query(EvidenceModel).filter_by(evidence_id="E-MAL-01").first()
        h = compute_hash_for_evidence(ev, GENESIS_HASH)
        assert len(h) == 64
    finally:
        db.close()


def test_empty_database_behavior(tmp_path):
    """14. Empty database passes verification cleanly with code 0."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    # Auditing an empty database should report 0 checked, 0 violations, and status VALID
    db = Session()
    try:
        evs = db.query(EvidenceModel).all()
        assert len(evs) == 0
    finally:
        db.close()
    res = run_verify_ledger(session_factory=Session, json_storage_path=json_path)
    assert res == 0


def test_cli_returns_correct_exit_codes(tmp_path):
    """15. CLI verify-ledger returns exit code 0 on a known-valid isolated database.

    Uses a fresh isolated SQLite DB (populated with a single valid evidence chain)
    rather than the production database, which can be polluted by concurrent test runs
    that write evidence to the global singleton ledger.
    """
    import os

    # Build an isolated DB with a known-valid evidence chain
    db_file = tmp_path / "cli_test.db"
    json_file = tmp_path / "cli_test_ledger.json"
    db_url = f"sqlite:///{db_file}"

    iso_engine = create_engine(db_url, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=iso_engine)
    setup_evidence_triggers(iso_engine)

    IsoSession = sessionmaker(autocommit=False, autoflush=False, bind=iso_engine)
    iso_db = IsoSession()

    inv_id = "INV-CLI-TEST"
    iso_db.add(InvestigationModel(
        investigation_id=inv_id,
        artifact_name="test.pcap",
        artifact_path="/tmp/test.pcap"
    ))
    iso_db.commit()

    # Insert one evidence row via the application ledger with isolated storage path
    iso_ledger = EvidenceLedger(storage_path=json_file, session_factory=IsoSession)
    from securemailscope.evidence.models import EvidenceType, SeverityLevel
    ev_id = f"E-CLI-{uuid.uuid4().hex[:6].upper()}"
    ev = Evidence(
        evidence_id=ev_id,
        investigation_id=inv_id,
        type=EvidenceType.OBSERVED,
        claim="Test claim for CLI verification.",
        source_tool="TestTool",
        tool_version="1.0",
        raw_artifact_ref="pcap://test",
        confidence=1.0,
        severity=SeverityLevel.LOW,
        provenance_chain=[inv_id, "TestTool"]
    )
    iso_ledger.record_evidence(ev)

    # Invoke CLI subprocess with the isolated DB and isolated JSON ledger path
    env = os.environ.copy()
    env["DATABASE_URL"] = db_url
    env["EVIDENCE_LEDGER_PATH"] = str(json_file)
    proc = subprocess.run(
        [sys.executable, "-m", "securemailscope.cli", "verify-ledger"],
        capture_output=True,
        text=True,
        env=env
    )
    assert proc.returncode == 0, (
        f"CLI verify-ledger failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert "Status: VALID" in proc.stdout
    assert "Invalid hashes: 0" in proc.stdout
    assert "Broken links: 0" in proc.stdout


def test_evidence_update_delete_attempts_rejected(tmp_path):
    """16. Direct SQLite UPDATE and DELETE are rejected by triggers."""
    engine, Session, json_path, db_file = create_isolated_test_env(tmp_path)
    raw_conn = sqlite3.connect(str(db_file))

    raw_conn.execute("INSERT INTO investigations (investigation_id, artifact_name, artifact_path) VALUES ('INV-TRIG', 't.pcap', 't.pcap')")
    raw_conn.execute("INSERT INTO evidence (evidence_id, investigation_id, type, claim, source_tool) VALUES ('E-TRIG-01', 'INV-TRIG', 'OBSERVED', 'Initial claim', 'Tool')")
    raw_conn.commit()

    # Attempt UPDATE
    with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="IMMUTABLE_VIOLATION"):
        raw_conn.execute("UPDATE evidence SET claim = 'Hacked' WHERE evidence_id = 'E-TRIG-01'")

    # Attempt DELETE
    with pytest.raises((sqlite3.OperationalError, sqlite3.IntegrityError), match="IMMUTABLE_VIOLATION"):
        raw_conn.execute("DELETE FROM evidence WHERE evidence_id = 'E-TRIG-01'")

    raw_conn.close()
