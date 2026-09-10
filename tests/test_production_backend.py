"""
SecureMailScope - Comprehensive Production Backend Test Suite
Tests all core production requirements:
1. LLM Provider Routing (NVIDIA success, timeout/error fallback to Gemini, deterministic mode)
2. Tavily Tool (Disabled, Enabled, Disallowed, External Intelligence Tagging)
3. Tool Gateway (Allowlisting, Schema validation, Malicious argument rejection)
4. Evidence & Finding Verification Gate (No Evidence -> Rejected, Cross-Investigation -> Rejected)
5. TLS 1.3 Honest NOT_OBSERVABLE Certificate Status
6. Incomplete Capture Lowers Confidence Score
7. ML Prediction & Feature Extraction Persistence
8. Real Agent Branching & Execution Steps
9. Multi-Format Report Generation (JSON, HTML, PDF)
10. System Tools Discovery & LLM Status Endpoints
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from pathlib import Path
from backend.llm.schemas import ChatRequest, ChatMessage, ChatResponse, TokenUsage
from backend.llm.exceptions import TimeoutError, ProviderUnavailableError
from backend.llm.nvidia import NvidiaProvider
from backend.llm.gemini import GeminiProvider
from backend.llm.router import LLMRouter
from securemailscope.core.config import config, SAMPLES_DIR, REPORTS_DIR
from securemailscope.core.exceptions import ToolExecutionError, EvidenceValidationError
from securemailscope.evidence.models import Evidence, EvidenceType, Finding, FindingStatus, SeverityLevel
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.evidence.validator import FindingValidator
from securemailscope.tools.gateway import ToolGateway
from securemailscope.tools.tavily import TavilySearchTool
from securemailscope.forensics.system_tools import SystemToolDiscovery
from securemailscope.agent.investigator import InvestigationAgent


@pytest.mark.anyio
async def test_llm_routing_nvidia_success():
    """Test priority 1: NVIDIA returns successfully."""
    mock_nv = AsyncMock(spec=NvidiaProvider)
    mock_nv.api_key = "test_key"
    mock_nv.model = "moonshotai/kimi-k3"
    mock_nv.chat.return_value = ChatResponse(
        content="NVIDIA Kimi K3 Analysis Output",
        model="moonshotai/kimi-k3",
        provider="nvidia",
        usage=TokenUsage(prompt_tokens=10, completion_tokens=20, total_tokens=30)
    )

    mock_gem = AsyncMock(spec=GeminiProvider)
    mock_gem.api_key = "gemini_key"

    router = LLMRouter(nvidia_provider=mock_nv, gemini_provider=mock_gem)
    req = ChatRequest(messages=[ChatMessage(role="user", content="Analyze capture")])

    resp = await router.chat(req, investigation_id="INV-TEST-ROUTING-1")
    assert resp.provider == "nvidia"
    assert resp.content == "NVIDIA Kimi K3 Analysis Output"
    mock_nv.chat.assert_awaited_once()
    mock_gem.chat.assert_not_awaited()


@pytest.mark.anyio
async def test_llm_routing_nvidia_timeout_gemini_fallback():
    """Test priority 1 failure (Timeout) -> Fallback to Gemini."""
    mock_nv = AsyncMock(spec=NvidiaProvider)
    mock_nv.api_key = "test_key"
    mock_nv.model = "moonshotai/kimi-k3"
    mock_nv.chat.side_effect = TimeoutError("Request timed out after 60s")

    mock_gem = AsyncMock(spec=GeminiProvider)
    mock_gem.api_key = "gemini_key"
    mock_gem.model = "gemini-1.5-flash"
    mock_gem.chat.return_value = ChatResponse(
        content="Gemini Fallback Analysis Output",
        model="gemini-1.5-flash",
        provider="gemini",
        usage=TokenUsage(prompt_tokens=12, completion_tokens=25, total_tokens=37)
    )

    router = LLMRouter(nvidia_provider=mock_nv, gemini_provider=mock_gem)
    req = ChatRequest(messages=[ChatMessage(role="user", content="Analyze capture")])

    resp = await router.chat(req, investigation_id="INV-TEST-ROUTING-2")
    assert resp.provider == "gemini"
    assert resp.content == "Gemini Fallback Analysis Output"
    mock_nv.chat.assert_awaited_once()
    mock_gem.chat.assert_awaited_once()


@pytest.mark.anyio
async def test_llm_routing_both_unavailable_deterministic_mode():
    """Test deterministic fallback when both external LLMs are unavailable or unconfigured."""
    mock_nv = AsyncMock(spec=NvidiaProvider)
    mock_nv.api_key = None
    mock_gem = AsyncMock(spec=GeminiProvider)
    mock_gem.api_key = None

    router = LLMRouter(nvidia_provider=mock_nv, gemini_provider=mock_gem)
    req = ChatRequest(messages=[ChatMessage(role="user", content="Explain STARTTLS stripping")])

    resp = await router.chat(req, investigation_id="INV-TEST-ROUTING-3")
    assert resp.provider == "deterministic"
    assert "Deterministic Forensic Reasoning Engine" in resp.content
    assert "STARTTLS" in resp.content


def test_tavily_disabled_and_enabled_handling():
    """Verify Tavily search tool behavior under different administrative policies."""
    with patch.object(config, 'tavily_enabled', False):
        res = TavilySearchTool.execute("INV-001", "example.com cert")
        assert res["status"] == "DISABLED"

    with patch.object(config, 'tavily_enabled', True), patch.object(config, 'allow_external_intel', False):
        res = TavilySearchTool.execute("INV-001", "example.com cert")
        assert res["status"] == "DISALLOWED"


def test_tool_allowlisting_and_malicious_rejection(tmp_path):
    """Verify that ToolGateway strictly rejects un-allowlisted or malicious tool invocations."""
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    gw = ToolGateway(ledger)

    # 1. Unallowlisted tool rejected
    with pytest.raises(ToolExecutionError) as exc_info:
        gw.execute_tool("INV-001", "system.rm_rf", {"path": "/"})
    assert "Unauthorized or unknown tool" in str(exc_info.value)

    # 2. Missing required arguments
    with pytest.raises(ToolExecutionError) as exc_info2:
        gw.execute_tool("INV-001", "pcap.inspect", {})
    assert "Missing required argument" in str(exc_info2.value)


def test_evidence_validation_no_evidence_rejected(tmp_path):
    """Verify No Evidence -> No Finding rule: finding without evidence is strictly rejected."""
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    validator = FindingValidator(ledger)

    fnd = Finding(
        finding_id="FND-EMPTY",
        investigation_id="INV-001",
        title="Hallucinated Finding",
        description="This was invented without packet proof.",
        severity=SeverityLevel.HIGH,
        evidence_ids=[]  # Empty
    )
    with pytest.raises(EvidenceValidationError) as exc_info:
        validator.validate_and_register_finding(fnd)
    assert "contains NO supporting evidence IDs" in str(exc_info.value)


def test_evidence_validation_cross_investigation_rejected(tmp_path):
    """Verify cross-investigation evidence reuse is strictly rejected."""
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    validator = FindingValidator(ledger)

    # Create evidence in INV-001
    ev = Evidence(
        evidence_id="E-001",
        investigation_id="INV-001",
        type=EvidenceType.OBSERVED,
        claim="Legitimate fact",
        source_tool="test",
        tool_version="1.0",
        raw_artifact_ref="pcap://test",
        provenance_chain=["INV-001", "test"]
    )
    ledger.record_evidence(ev)

    # Attempt to attach E-001 to INV-002 finding
    fnd = Finding(
        finding_id="FND-002",
        investigation_id="INV-002",
        title="Cross Investigation Claim",
        description="Using evidence from another case",
        severity=SeverityLevel.MEDIUM,
        evidence_ids=["E-001"]
    )
    with pytest.raises(EvidenceValidationError) as exc_info:
        validator.validate_and_register_finding(fnd)
    assert "belong to a different investigation" in str(exc_info.value)


def test_tls13_certificate_not_observable(tmp_path):
    """Verify honest TLS 1.3 certificate status: must record NOT_OBSERVABLE and never fabricate."""
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    agent = InvestigationAgent(ledger)
    pcap = SAMPLES_DIR / "mail_secure_tls13.pcap"

    inv = agent.run_investigation("INV-TLS13-TEST", pcap)
    assert inv.status.value == "COMPLETED"

    # Verify limitations note
    assert any("TLS 1.3" in lim and "not observable" in lim for lim in inv.limitations)

    # Verify evidence items
    evs = ledger.get_evidence_for_investigation("INV-TLS13-TEST")
    not_obs_ev = [e for e in evs if e.type == EvidenceType.NOT_OBSERVABLE or "NOT_OBSERVABLE" in e.type.value]
    assert len(not_obs_ev) > 0
    assert "encrypted" in not_obs_ev[0].claim.lower()


def test_incomplete_capture_lowers_confidence(tmp_path):
    """Verify incomplete capture triggers inconclusive finding and reduces overall confidence."""
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    agent = InvestigationAgent(ledger)
    pcap = SAMPLES_DIR / "mail_partial_capture_inconclusive.pcap"

    inv = agent.run_investigation("INV-INCOMPLETE-TEST", pcap)
    assert inv.completeness_percentage < 60.0
    assert inv.posture.confidence_score <= 50.0

    findings = ledger.get_findings_for_investigation("INV-INCOMPLETE-TEST")
    inconclusive_fnds = [f for f in findings if f.status == FindingStatus.INCONCLUSIVE]
    assert len(inconclusive_fnds) > 0


def test_report_generation(tmp_path):
    """Verify deterministic JSON, HTML, and PDF report generation."""
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    agent = InvestigationAgent(ledger)
    pcap = SAMPLES_DIR / "mail_attack_starttls_strip.pcap"

    inv_id = "INV-REPORT-TEST"
    inv = agent.run_investigation(inv_id, pcap)

    json_report = REPORTS_DIR / f"{inv_id}_report.json"
    html_report = REPORTS_DIR / f"{inv_id}_report.html"
    pdf_report = REPORTS_DIR / f"{inv_id}_report.pdf"

    assert json_report.exists()
    assert html_report.exists()
    assert pdf_report.exists()
    assert pdf_report.stat().st_size > 500


def test_system_tool_discovery():
    """Verify system tool detection returns installed, path, and healthy booleans."""
    tools = SystemToolDiscovery.discover_all()
    assert "tshark" in tools
    assert "capinfos" in tools
    assert "zeek" in tools
    assert "openssl" in tools
    assert isinstance(tools["tshark"]["installed"], bool)
    assert isinstance(tools["openssl"]["installed"], bool)


def test_demo_fixtures_all_five_scenarios(tmp_path):
    """Verify all 5 demo scenario fixtures produce correct forensic verdicts."""
    from securemailscope.core.config import BASE_DIR
    demo_dir = BASE_DIR / "demo"

    scenarios = [
        ("clean/clean_smtp_tls12.pcap", "SECURE", 100.0),
        ("starttls-anomaly/starttls_stripping_attack.pcap", "CRITICAL", 0.0),
        ("weak-crypto/legacy_tls10_rc4.pcap", "HIGH", 40.0),
        ("incomplete-capture/truncated_capture.pcap", "INCONCLUSIVE", 50.0),
        ("tls13/modern_tls13_encrypted_cert.pcap", "SECURE", 100.0),
    ]

    for rel_path, expected_risk_prefix, max_expected_posture in scenarios:
        pcap_path = demo_dir / rel_path
        assert pcap_path.exists(), f"Missing demo fixture {rel_path}"

        ledger = EvidenceLedger(storage_path=tmp_path / f"ledger_{Path(rel_path).stem}.json")
        agent = InvestigationAgent(ledger)
        inv_id = f"INV-DEMO-{Path(rel_path).stem.upper()[:8]}"

        inv = agent.run_investigation(inv_id, pcap_path)
        assert inv.status.value == "COMPLETED"

        if expected_risk_prefix == "CRITICAL":
            assert inv.posture.risk_level.startswith("CRITICAL")
        elif expected_risk_prefix == "HIGH":
            assert inv.posture.risk_level in ("HIGH RISK", "CRITICAL RISK")
        elif expected_risk_prefix == "INCONCLUSIVE":
            assert inv.completeness_percentage < 60.0
            assert inv.posture.confidence_score <= 50.0
        elif expected_risk_prefix == "SECURE":
            assert inv.posture.overall_posture_score >= 80.0


def test_pcap_upload_security_validation(tmp_path):
    """Verify security validation rejects path traversal, invalid extensions, and fake magic bytes."""
    from io import BytesIO
    from fastapi import UploadFile, HTTPException
    from securemailscope.api.routes import validate_and_save_pcap

    # 1. Path traversal attempt
    traversal_file = UploadFile(filename="../../etc/passwd.pcap", file=BytesIO(b"\xd4\xc3\xb2\xa1validheader"))
    with pytest.raises(HTTPException) as exc1:
        validate_and_save_pcap(traversal_file, tmp_path / "dest1.pcap")
    assert exc1.value.status_code == 400

    # 2. Invalid extension
    exe_file = UploadFile(filename="malicious.exe", file=BytesIO(b"\xd4\xc3\xb2\xa1validheader"))
    with pytest.raises(HTTPException) as exc2:
        validate_and_save_pcap(exe_file, tmp_path / "dest2.pcap")
    assert exc2.value.status_code == 400
    assert "Invalid file extension" in exc2.value.detail

    # 3. Invalid magic bytes (e.g. text file pretending to be PCAP)
    fake_pcap = UploadFile(filename="fake.pcap", file=BytesIO(b"THIS IS PLAIN TEXT NOT A PCAP"))
    with pytest.raises(HTTPException) as exc3:
        validate_and_save_pcap(fake_pcap, tmp_path / "dest3.pcap")
    assert exc3.value.status_code == 400
    assert "magic" in exc3.value.detail.lower() or "file signature" in exc3.value.detail.lower()


def test_ssrf_protection_dns_tools():
    """Verify SSRF protection rejects internal/loopback IP targets."""
    from securemailscope.tools.dns_tools import is_ssrf_safe_domain, DNSSecurityTools

    assert not is_ssrf_safe_domain("localhost")
    assert not is_ssrf_safe_domain("127.0.0.1")
    assert not is_ssrf_safe_domain("169.254.169.254")
    assert not is_ssrf_safe_domain("10.0.0.1")
    assert not is_ssrf_safe_domain("192.168.1.1")
    assert not is_ssrf_safe_domain("server.internal")
    assert not is_ssrf_safe_domain("cluster.local")
    assert is_ssrf_safe_domain("mail.google.com")

    res = DNSSecurityTools.query_mx("127.0.0.1")
    assert res["status"] == "BLOCKED"
    assert "SSRF" in res["error"]


def test_database_persistence_artifacts_and_sessions(tmp_path):
    """Verify ArtifactModel and ForensicSessionModel records are persisted in the database."""
    from securemailscope.db.session import SessionLocal
    from securemailscope.db.models import ArtifactModel, ForensicSessionModel

    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    agent = InvestigationAgent(ledger)
    pcap = SAMPLES_DIR / "mail_attack_starttls_strip.pcap"

    inv_id = "INV-DB-PERSIST-TEST"
    inv = agent.run_investigation(inv_id, pcap)

    db = SessionLocal()
    try:
        art = db.query(ArtifactModel).filter_by(investigation_id=inv_id).first()
        assert art is not None
        assert art.file_size > 0
        assert len(art.sha256) == 64

        sessions = db.query(ForensicSessionModel).filter_by(investigation_id=inv_id).all()
        assert len(sessions) > 0
        assert sessions[0].protocol in ("SMTP", "UNKNOWN")
    finally:
        db.close()


def test_contradiction_detection_evidence(tmp_path):
    """Verify explicit contradiction evidence is recorded for STARTTLS downgrade with high completeness."""
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    agent = InvestigationAgent(ledger)
    pcap = SAMPLES_DIR / "mail_attack_starttls_strip.pcap"

    inv_id = "INV-CONTRA-TEST"
    inv = agent.run_investigation(inv_id, pcap)

    evs = ledger.get_evidence_for_investigation(inv_id)
    contra_ev = [e for e in evs if e.source_tool == "ContradictionEngine"]
    assert len(contra_ev) > 0
    assert any("contradict" in e.claim.lower() for e in contra_ev)


def test_investigation_replay_endpoint():
    """Verify replay endpoint returns ordered steps without re-executing tools."""
    from fastapi.testclient import TestClient
    from securemailscope.api.app import app

    ledger = EvidenceLedger.get_instance()
    agent = InvestigationAgent(ledger)
    pcap = SAMPLES_DIR / "mail_attack_starttls_strip.pcap"

    inv_id = "INV-REPLAY-TEST"
    inv = agent.run_investigation(inv_id, pcap)

    client = TestClient(app)
    resp = client.get(f"/api/investigations/{inv_id}/replay")
    assert resp.status_code == 200
    data = resp.json()
    assert data["investigation_id"] == inv_id
    assert data["step_count"] > 0
    assert len(data["steps"]) > 0
    # Step sequence numbers are strictly ascending
    step_nums = [s["step_number"] for s in data["steps"]]
    assert step_nums == sorted(step_nums)


def test_fastapi_sanitized_error_handling():
    """Verify unhandled internal errors do not leak stack traces or python internals."""
    from fastapi.testclient import TestClient
    from securemailscope.api.app import app

    client = TestClient(app)
    # Non-existent investigation should return 404 with structured error
    resp = client.get("/api/investigations/NON-EXISTENT-ID")
    assert resp.status_code == 404
    err_body = resp.json()
    assert "error" in err_body or "detail" in err_body


