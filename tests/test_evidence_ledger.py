"""
Unit tests for Evidence Ledger and Finding Validator ("No Evidence -> No Finding")
"""
import pytest
from securemailscope.evidence.models import Evidence, EvidenceType, Finding, FindingStatus, SeverityLevel
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.evidence.validator import FindingValidator
from securemailscope.core.exceptions import EvidenceValidationError


def test_evidence_ledger_persistence(tmp_path):
    ledger = EvidenceLedger(storage_path=tmp_path / "test_ledger.json")
    ev = Evidence(
        evidence_id="E-TEST-001",
        investigation_id="INV-TEST-01",
        type=EvidenceType.TLS_VERSION_DETECTED,
        claim="TLS 1.2 negotiated",
        source_tool="TLSEngine",
        tool_version="1.0",
        raw_artifact_ref="pcap://test",
        confidence=1.0,
        provenance_chain=["INV-TEST-01", "test.pcap", "TLSEngine"]
    )
    ledger.record_evidence(ev)

    # Fetch back
    fetched = ledger.get_evidence("E-TEST-001")
    assert fetched is not None
    assert fetched.claim == "TLS 1.2 negotiated"


def test_finding_validator_accepts_valid_finding(tmp_path):
    ledger = EvidenceLedger(storage_path=tmp_path / "test_ledger.json")
    validator = FindingValidator(ledger)

    ev = Evidence(
        evidence_id="E-VALID-01",
        investigation_id="INV-01",
        type=EvidenceType.PLAINTEXT_CONTINUATION,
        claim="Plaintext continuation observed",
        source_tool="SMTPAnalyzer",
        tool_version="1.0",
        raw_artifact_ref="pcap://mail.pcap",
        provenance_chain=["INV-01", "mail.pcap", "SMTPAnalyzer"]
    )
    ledger.record_evidence(ev)

    finding = Finding(
        finding_id="FND-01",
        investigation_id="INV-01",
        title="STARTTLS Downgrade",
        description="Observed plaintext fallback",
        severity=SeverityLevel.CRITICAL,
        evidence_ids=["E-VALID-01"]
    )

    valid, msg = validator.validate_and_register_finding(finding)
    assert valid is True
    assert finding.status == FindingStatus.VERIFIED


def test_finding_validator_rejects_empty_evidence(tmp_path):
    ledger = EvidenceLedger(storage_path=tmp_path / "test_ledger.json")
    validator = FindingValidator(ledger)

    finding = Finding(
        finding_id="FND-FAKE",
        investigation_id="INV-01",
        title="Fabricated Vulnerability",
        description="Made up claim with no evidence",
        severity=SeverityLevel.CRITICAL,
        evidence_ids=[]  # Empty evidence
    )

    with pytest.raises(EvidenceValidationError, match="contains NO supporting evidence IDs"):
        validator.validate_and_register_finding(finding)


def test_finding_validator_rejects_nonexistent_evidence(tmp_path):
    ledger = EvidenceLedger(storage_path=tmp_path / "test_ledger.json")
    validator = FindingValidator(ledger)

    finding = Finding(
        finding_id="FND-FAKE-2",
        investigation_id="INV-01",
        title="Fabricated Claim",
        description="Claim referencing non-existent evidence ID",
        severity=SeverityLevel.CRITICAL,
        evidence_ids=["E-NON-EXISTENT-999"]
    )

    with pytest.raises(EvidenceValidationError, match="Evidence IDs do not exist in Ledger"):
        validator.validate_and_register_finding(finding)
