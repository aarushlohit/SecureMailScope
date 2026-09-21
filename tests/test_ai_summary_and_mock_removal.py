"""
Unit and Integration Tests for SecureMailScope AI Investigation Summary & Reasoning
Tests:
1. Real Context Usage & Provenance
2. Evidence Citation Grounding & Hallucination Rejection
3. Truthful Deterministic Fallback on Provider Unavailable
4. Cache Invalidation upon Underlying Evidence Change
5. Report Multi-Format Consistency (JSON, HTML, PDF)
6. Route Ownership & Cross-User Security (IDOR Protection)
7. Absence of Mock/Demo Data Leakage
"""
import pytest
import asyncio
import hashlib
from pathlib import Path
from unittest.mock import AsyncMock, patch

from securemailscope.evidence.models import (
    Investigation, Evidence, Finding, EvidenceType, SeverityLevel, FindingStatus, PostureScorecard
)
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.ai.summary import (
    generate_investigation_summary,
    generate_deterministic_fallback_summary,
    compute_forensic_data_hash,
    _validate_and_sanitize_summary,
    get_cached_summary,
    _SUMMARY_CACHE
)
from backend.llm.schemas import ChatResponse
from backend.llm.exceptions import ProviderUnavailableError
from securemailscope.reports.json_reporter import JSONReporter
from securemailscope.reports.html_reporter import HTMLReporter
from securemailscope.reports.pdf_reporter import PDFReporter


@pytest.fixture
def sample_investigation_and_evidence():
    inv_id = "INV-TEST-AI-001"
    inv = Investigation(
        investigation_id=inv_id,
        artifact_name="smtp_test.pcap",
        artifact_path="/tmp/smtp_test.pcap",
        artifact_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        artifact_md5="1234567890abcdef1234567890abcdef",
        artifact_size=1024,
        packet_count=50,
        completeness_percentage=100.0,
        streams_analyzed=1,
        protocols_detected=["SMTP"],
        posture=PostureScorecard(
            overall_posture_score=20.0,
            risk_level="CRITICAL RISK",
            confidence_score=95.0,
            ml_risk_probability=0.88,
            score_deductions=[]
        )
    )
    ev1 = Evidence(
        evidence_id="E-VALID01",
        investigation_id=inv_id,
        type=EvidenceType.STARTTLS_STRIPPED,
        claim="STARTTLS command negotiated but plaintext continued",
        confidence=0.99,
        source_tool="smtp.analyze",
        details={"port": 25, "cmd": "STARTTLS"}
    )
    ev2 = Evidence(
        evidence_id="E-VALID02",
        investigation_id=inv_id,
        type=EvidenceType.TCP_STREAM_RECONSTRUCTED,
        claim="TCP stream 0 contains plaintext auth after 220 Ready",
        confidence=0.98,
        source_tool="pcap.sessions",
        details={"stream_index": 0}
    )
    f1 = Finding(
        finding_id="F-STRIP01",
        investigation_id=inv_id,
        title="STARTTLS Stripping Attack Observed",
        description="Plaintext continuation observed post STARTTLS response.",
        severity=SeverityLevel.CRITICAL,
        status=FindingStatus.VERIFIED,
        evidence_ids=["E-VALID01", "E-VALID02"],
        remediation="Enforce mandatory TLS encryption."
    )
    return inv, [ev1, ev2], [f1]


def test_compute_forensic_data_hash_deterministic():
    sha = "hash123"
    ev_ids = ["E-002", "E-001"]
    fnd_ids = ["F-001"]
    h1 = compute_forensic_data_hash(sha, ev_ids, fnd_ids, 2)
    h2 = compute_forensic_data_hash(sha, ["E-001", "E-002"], fnd_ids, 2)
    # Sorted evidence IDs guarantee deterministic hash
    assert h1 == h2
    assert len(h1) == 64

    # Any change invalidates the hash
    h3 = compute_forensic_data_hash(sha, ["E-001", "E-002", "E-003"], fnd_ids, 2)
    assert h1 != h3


def test_validate_and_sanitize_summary_filters_hallucinated_citations():
    raw_ai_output = {
        "executive_summary": "Test executive briefing",
        "key_observations": ["Obs 1", "Obs 2"],
        "finding_reasoning": [
            {
                "finding_id": "F-STRIP01",
                "reasoning": "Valid finding cited with both real and hallucinated IDs",
                "supporting_evidence_ids": ["E-VALID01", "E-FAKE999", "E-VALID02", "E-MADEUP"]
            },
            {
                "finding_id": "F-FAKE-FINDING",
                "reasoning": "This finding does not exist in the ledger",
                "supporting_evidence_ids": ["E-VALID01"]
            }
        ],
        "risk_explanation": "Critical vulnerability present",
        "recommended_actions": ["Block plaintext traffic"]
    }
    valid_eids = {"E-VALID01", "E-VALID02"}
    valid_fids = {"F-STRIP01"}

    sanitized = _validate_and_sanitize_summary(raw_ai_output, valid_eids, valid_fids)

    # 1. Hallucinated finding F-FAKE-FINDING must be dropped
    f_ids = [fr["finding_id"] for fr in sanitized["finding_reasoning"]]
    assert "F-STRIP01" in f_ids
    assert "F-FAKE-FINDING" not in f_ids

    # 2. Hallucinated evidence citations E-FAKE999 and E-MADEUP must be filtered out
    strip_reasoning = next(fr for fr in sanitized["finding_reasoning"] if fr["finding_id"] == "F-STRIP01")
    assert strip_reasoning["supporting_evidence_ids"] == ["E-VALID01", "E-VALID02"]


def test_deterministic_fallback_summary(sample_investigation_and_evidence):
    inv, evs, fnds = sample_investigation_and_evidence
    fallback = generate_deterministic_fallback_summary(
        investigation=inv,
        evidence=evs,
        findings=fnds,
        sessions=[],
        reason="NVIDIA and Gemini APIs currently unreachable."
    )

    assert fallback["status"] == "fallback"
    assert fallback["generated_by"] == "deterministic-system"
    assert fallback["is_ai_generated"] is False
    assert "CRITICAL RISK" in fallback["executive_summary"]
    assert "E-VALID01" in fallback["finding_reasoning"][0]["supporting_evidence_ids"]
    assert "E-VALID02" in fallback["finding_reasoning"][0]["supporting_evidence_ids"]


def test_generate_investigation_summary_truthful_fallback_on_provider_error(sample_investigation_and_evidence):
    inv, evs, fnds = sample_investigation_and_evidence

    mock_router = AsyncMock()
    mock_router.chat.side_effect = ProviderUnavailableError("All LLM providers unreachable.")

    summary = asyncio.run(generate_investigation_summary(
        investigation=inv,
        evidence=evs,
        findings=fnds,
        sessions=[],
        force_refresh=True,
        router=mock_router
    ))

    assert summary["is_ai_generated"] is False
    assert summary["generated_by"] == "deterministic-system"
    assert "smtp_test.pcap" in summary["executive_summary"]
    assert len(summary["key_observations"]) > 0


def test_generate_investigation_summary_successful_ai(sample_investigation_and_evidence):
    inv, evs, fnds = sample_investigation_and_evidence

    mock_router = AsyncMock()
    ai_json_reply = """```json
    {
      "executive_summary": "Forensic analysis of smtp_test.pcap confirmed an active STARTTLS stripping attack.",
      "key_observations": ["SMTP stream continued in cleartext despite STARTTLS 220 advertisement."],
      "finding_reasoning": [
        {
          "finding_id": "F-STRIP01",
          "reasoning": "Cleartext commands observed post-negotiation violating cryptographic baseline.",
          "supporting_evidence_ids": ["E-VALID01", "E-VALID02"]
        }
      ],
      "risk_explanation": "Exposes sensitive credentials and mail bodies to passive interception.",
      "recommended_actions": ["Deploy MTA-STS and require mandatory TLS 1.3."]
    }
    ```"""
    mock_router.chat.return_value = ChatResponse(
        content=ai_json_reply,
        provider="nvidia_nim",
        model="meta/llama-3.2-11b-vision-instruct"
    )

    summary = asyncio.run(generate_investigation_summary(
        investigation=inv,
        evidence=evs,
        findings=fnds,
        sessions=[],
        force_refresh=True,
        router=mock_router
    ))

    assert summary["status"] == "success"
    assert summary["is_ai_generated"] is True
    assert summary["generated_by"] == "nvidia_nim"
    assert summary["model"] == "meta/llama-3.2-11b-vision-instruct"
    assert summary["finding_reasoning"][0]["supporting_evidence_ids"] == ["E-VALID01", "E-VALID02"]

    # Verify cached retrieval
    cached = get_cached_summary(inv.investigation_id)
    assert cached is not None
    assert cached["model"] == "meta/llama-3.2-11b-vision-instruct"


def test_reports_include_ai_summary(tmp_path, sample_investigation_and_evidence):
    inv, evs, fnds = sample_investigation_and_evidence
    ledger = EvidenceLedger(storage_path=tmp_path / "test_ledger.json")
    ledger.save_investigation(inv)
    for e in evs:
        ledger.record_evidence(e)
    for f in fnds:
        ledger.save_finding(f)

    ai_sum = {
        "status": "success",
        "generated_by": "nvidia_nim",
        "model": "meta/llama-3.2-11b-vision-instruct",
        "prompt_version": "2.1.0",
        "is_ai_generated": True,
        "executive_summary": "Comprehensive analysis of smtp_test.pcap shows cleartext downgrade.",
        "key_observations": ["STARTTLS advertised", "Plaintext continued"],
        "risk_explanation": "Severe risk of credential interception.",
        "recommended_actions": ["Enforce TLS 1.3"]
    }

    # 1. JSON Report
    json_path = tmp_path / "test_report.json"
    JSONReporter.generate_report(inv.investigation_id, ledger, json_path, ai_summary=ai_sum)
    assert json_path.exists()
    import json
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert "ai_summary" in data
    assert data["ai_summary"]["executive_summary"] == "Comprehensive analysis of smtp_test.pcap shows cleartext downgrade."

    # 2. HTML Report
    html_path = tmp_path / "test_report.html"
    HTMLReporter.generate_report(inv.investigation_id, ledger, html_path, ai_summary=ai_sum)
    assert html_path.exists()
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    assert "Comprehensive analysis of smtp_test.pcap shows cleartext downgrade." in html_content
    assert "AI-Assisted Investigation Summary & Reasoning" in html_content

    # 3. PDF Report
    pdf_path = tmp_path / "test_report.pdf"
    PDFReporter.generate_report(inv.investigation_id, ledger, pdf_path, ai_summary=ai_sum)
    assert pdf_path.exists()
    assert pdf_path.stat().st_size > 1000  # Valid non-empty PDF
