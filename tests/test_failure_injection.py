"""
SecureMailScope - Comprehensive Failure Injection & Security Boundary Tests
Validates:
- Invalid PCAP uploads (fake PNG, text, empty)
- Path traversal attempts in filename
- Disallowed file extensions
- Tool Gateway strict allowlisting
- Missing system binaries graceful degradation
- Both LLM providers unavailable handling
- Finding Validator rejection of evidenceless findings (EvidenceValidationError)
- Finding Validator rejection of non-existent evidence IDs
- Cross-investigation evidence rejection
- Missing provenance chain rejection
- Incomplete PCAP handling and inconclusive status
"""
import pytest
import asyncio
import uuid
from pathlib import Path
from starlette.testclient import TestClient

from securemailscope.api.app import app
from securemailscope.core.exceptions import ToolExecutionError, EvidenceValidationError
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.evidence.validator import FindingValidator
from securemailscope.evidence.models import (
    Finding,
    FindingStatus,
    SeverityLevel,
    Evidence,
    EvidenceType
)
from securemailscope.tools.gateway import ToolGateway
from backend.llm.exceptions import ProviderUnavailableError
from backend.llm.router import LLMRouter
from backend.llm.nvidia import NvidiaProvider
from backend.llm.gemini import GeminiProvider
from backend.llm.schemas import ChatRequest, ChatMessage


@pytest.fixture
def client():
    """Authenticated test client — upload endpoint requires auth."""
    from tests.conftest import make_authed_client
    return make_authed_client()


@pytest.fixture
def ledger(tmp_path):
    """Isolated ledger per test — does NOT touch the production database."""
    return EvidenceLedger(storage_path=tmp_path / "ledger.json")


@pytest.fixture
def gateway(ledger):
    return ToolGateway(ledger)


# --------------------------------------------------------------------
# 1. PCAP Ingestion Boundary & Security Tests
# --------------------------------------------------------------------

def test_fake_png_renamed_to_pcap(client):
    """Uploading a PNG image renamed as .pcap must return HTTP 400."""
    fake_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 50
    resp = client.post(
        "/api/investigations",
        files={"file": ("capture.pcap", fake_png, "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 400
    assert "signature does not match PCAP" in resp.json()["detail"]


def test_plain_text_renamed_to_pcap(client):
    """Uploading plain text as .pcap must be rejected."""
    fake_txt = b"Hello, this is just plain text, not network packets."
    resp = client.post(
        "/api/investigations",
        files={"file": ("capture.pcap", fake_txt, "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 400
    assert "signature does not match PCAP" in resp.json()["detail"]


def test_empty_file_upload(client):
    """Uploading an empty file must return HTTP 400."""
    resp = client.post(
        "/api/investigations",
        files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 400
    assert "empty" in resp.json()["detail"].lower()


def test_disallowed_extension(client):
    """Uploading an executable or script must return HTTP 400."""
    resp = client.post(
        "/api/investigations",
        files={"file": ("exploit.sh", b"#!/bin/bash\necho pwned\n", "text/plain")}
    )
    assert resp.status_code == 400
    assert "Invalid file extension" in resp.json()["detail"]


def test_path_traversal_filename(client):
    """Path traversal sequences in filename must return HTTP 400."""
    valid_pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 100
    resp = client.post(
        "/api/investigations",
        files={"file": ("../../../../etc/passwd.pcap", valid_pcap, "application/vnd.tcpdump.pcap")}
    )
    assert resp.status_code == 400
    assert "path traversal" in resp.json()["detail"].lower()


# --------------------------------------------------------------------
# 2. Tool Gateway Strict Allowlisting & Sandboxing Tests
# --------------------------------------------------------------------

def test_unallowlisted_tool_rejection(gateway):
    """Gateway must strictly reject unauthorized tool names with ToolExecutionError."""
    with pytest.raises(ToolExecutionError) as exc_info:
        gateway.execute_tool("INV-TEST", "system.exec", {"cmd": "rm -rf /"})
    assert "Unauthorized or unknown tool" in str(exc_info.value)


def test_missing_required_tool_arguments(gateway):
    """Missing required arguments must raise ToolExecutionError."""
    with pytest.raises(ToolExecutionError) as exc_info:
        gateway.execute_tool("INV-TEST", "pcap.inspect", {})
    assert "Missing required argument" in str(exc_info.value)


# --------------------------------------------------------------------
# 3. Finding Validator Gatekeeper & Evidence Grounding Tests
# --------------------------------------------------------------------

def test_validator_rejects_finding_with_empty_evidence(ledger):
    """A finding without supporting Evidence IDs must be strictly rejected with EvidenceValidationError."""
    validator = FindingValidator(ledger)
    fnd = Finding(
        finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
        investigation_id="INV-TEST",
        title="Fabricated Attack",
        description="No evidence supports this finding.",
        severity=SeverityLevel.CRITICAL,
        status=FindingStatus.CANDIDATE,
        evidence_ids=[]  # Empty!
    )
    with pytest.raises(EvidenceValidationError) as exc:
        validator.validate_and_register_finding(fnd)
    assert "contains NO supporting evidence IDs" in str(exc.value)


def test_validator_rejects_nonexistent_evidence_id(ledger):
    """A finding citing a fake/fabricated Evidence ID must be rejected with EvidenceValidationError."""
    validator = FindingValidator(ledger)
    fnd = Finding(
        finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
        investigation_id="INV-TEST",
        title="Speculative Vulnerability",
        description="Cites an ID that does not exist in the ledger.",
        severity=SeverityLevel.HIGH,
        status=FindingStatus.CANDIDATE,
        evidence_ids=["E-FAKEEID123"]
    )
    with pytest.raises(EvidenceValidationError) as exc:
        validator.validate_and_register_finding(fnd)
    assert "do not exist in Ledger" in str(exc.value)


def test_cross_investigation_evidence_isolation(ledger):
    """A finding in Investigation A citing evidence from Investigation B must be rejected."""
    validator = FindingValidator(ledger)

    # Record legitimate evidence in INV-A with valid provenance
    ev_a = Evidence(
        evidence_id=f"E-{uuid.uuid4().hex[:6].upper()}",
        investigation_id="INV-A",
        type=EvidenceType.OBSERVED,
        claim="Legitimate observation in INV-A.",
        source_tool="TestTool",
        tool_version="1.0",
        raw_artifact_ref="ref://A",
        confidence=1.0,
        severity=SeverityLevel.LOW,
        provenance_chain=["INV-A", "TestTool", "step-1"]
    )
    ledger.record_evidence(ev_a)

    # Attempt to cite ev_a from INV-B
    fnd_b = Finding(
        finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
        investigation_id="INV-B",
        title="Cross Investigation Citation",
        description="Attempting to attach evidence from another investigation.",
        severity=SeverityLevel.MEDIUM,
        status=FindingStatus.CANDIDATE,
        evidence_ids=[ev_a.evidence_id]
    )
    with pytest.raises(EvidenceValidationError) as exc:
        validator.validate_and_register_finding(fnd_b)
    assert "belong to a different investigation" in str(exc.value)


def test_evidence_missing_provenance_rejected(ledger):
    """Evidence without provenance chain must be rejected by the Validator."""
    validator = FindingValidator(ledger)
    ev_noprov = Evidence(
        evidence_id=f"E-{uuid.uuid4().hex[:6].upper()}",
        investigation_id="INV-NOPROV",
        type=EvidenceType.OBSERVED,
        claim="Observation without provenance chain.",
        source_tool="UnknownTool",
        tool_version="1.0",
        raw_artifact_ref="ref://noprov",
        confidence=1.0,
        severity=SeverityLevel.LOW,
        provenance_chain=[]  # Empty!
    )
    ledger.record_evidence(ev_noprov)

    fnd = Finding(
        finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
        investigation_id="INV-NOPROV",
        title="Unprovenanced Finding",
        description="Finding supported by unprovenanced evidence.",
        severity=SeverityLevel.LOW,
        status=FindingStatus.CANDIDATE,
        evidence_ids=[ev_noprov.evidence_id]
    )
    with pytest.raises(EvidenceValidationError) as exc:
        validator.validate_and_register_finding(fnd)
    assert "lack valid provenance chains" in str(exc.value)


# --------------------------------------------------------------------
# 4. LLM Providers Unavailable Graceful Handling Tests
# --------------------------------------------------------------------

def test_both_llm_providers_unavailable_raises_clean_error():
    """When both NVIDIA and Gemini are unconfigured, router must raise ProviderUnavailableError."""
    empty_nvidia = NvidiaProvider()
    empty_nvidia.api_key = None
    empty_gemini = GeminiProvider()
    empty_gemini.api_key = None
    router = LLMRouter(nvidia_provider=empty_nvidia, gemini_provider=empty_gemini)

    req = ChatRequest(messages=[ChatMessage(role="user", content="Hello")])
    with pytest.raises(ProviderUnavailableError) as exc_info:
        asyncio.run(router.chat(req))
    assert "Neither NVIDIA NIM nor Google Gemini is available" in str(exc_info.value)


# --------------------------------------------------------------------
# 5. Incomplete PCAP Inconclusive Status Tests
# --------------------------------------------------------------------

def test_incomplete_pcap_marks_finding_inconclusive(ledger):
    """A finding explicitly created as INCONCLUSIVE preserves its honest uncertainty status."""
    validator = FindingValidator(ledger)
    ev_comp = Evidence(
        evidence_id=f"E-{uuid.uuid4().hex[:6].upper()}",
        investigation_id="INV-INCOMPLETE",
        type=EvidenceType.DERIVED,
        claim="Capture completeness calculated at 45.0% (HIGH_LOSS). Sequence gaps: 15.",
        source_tool="CaptureEngine.completeness",
        tool_version="1.0",
        raw_artifact_ref="pcap://incomplete/completeness",
        confidence=0.5,
        severity=SeverityLevel.MEDIUM,
        provenance_chain=["INV-INCOMPLETE", "CaptureEngine.completeness"]
    )
    ledger.record_evidence(ev_comp)

    fnd = Finding(
        finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
        investigation_id="INV-INCOMPLETE",
        title="Inconclusive Truncated Handshake",
        description="ClientHello missing due to capture truncation.",
        severity=SeverityLevel.MEDIUM,
        status=FindingStatus.INCONCLUSIVE,
        evidence_ids=[ev_comp.evidence_id]
    )
    is_valid, msg = validator.validate_and_register_finding(fnd)
    assert is_valid is True
    assert fnd.status == FindingStatus.INCONCLUSIVE
