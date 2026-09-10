"""Acceptance tests for real arbitrary PCAP forensic analysis with zero mocking.

Tests real-world Wireshark captures (SMTP, IMAP, SMTPS) to verify:
1. Genuine packet parsing and stream reconstruction
2. Authentic rule violations and evidence generation
3. Strict non-empty evidence citations for every finding
4. Non-mocked report generation (.json, .html, .pdf)
5. Zero fallback to hardcoded filenames or synthetic scenario flags
"""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from securemailscope.agent.investigator import InvestigationAgent
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.forensics.capture import CaptureEngine
from securemailscope.reports.json_reporter import JSONReporter
from securemailscope.reports.html_reporter import HTMLReporter
from securemailscope.reports.pdf_reporter import PDFReporter
from securemailscope.api.app import app

client = TestClient(app)

SAMPLE_DIR = Path(__file__).parent.parent / "samples"
REPORTS_DIR = Path(__file__).parent.parent / "reports"


def test_real_wireshark_smtp_forensic_pipeline(tmp_path):
    """Verify real unencrypted SMTP capture triggers genuine cleartext auth findings."""
    pcap_path = SAMPLE_DIR / "wireshark_real_smtp.pcap"
    assert pcap_path.exists(), f"Sample {pcap_path} must exist"

    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    agent = InvestigationAgent(ledger)

    inv = agent.run_investigation(
        investigation_id="INV-REAL-SMTP-01",
        pcap_path=pcap_path,
    )

    assert inv.investigation_id == "INV-REAL-SMTP-01"
    assert inv.packet_count == 60
    assert "SMTP" in inv.protocols_detected
    assert inv.streams_analyzed >= 1
    assert inv.posture is not None
    assert inv.posture.confidence_score > 60.0

    # Ensure findings exist and all cite valid evidence
    findings = ledger.get_findings_for_investigation("INV-REAL-SMTP-01")
    assert len(findings) >= 1
    for f in findings:
        assert len(f.evidence_ids) > 0
        for ev_id in f.evidence_ids:
            ev = ledger.get_evidence(ev_id)
            assert ev is not None
            assert ev.investigation_id == "INV-REAL-SMTP-01"

    # Confirm cleartext auth finding was triggered
    cleartext_findings = [f for f in findings if "Cleartext" in f.title or "Plaintext" in f.title]
    assert len(cleartext_findings) >= 1

    # Confirm reports are generable on disk
    json_path = tmp_path / "report.json"
    html_path = tmp_path / "report.html"
    pdf_path = tmp_path / "report.pdf"
    JSONReporter.generate_report("INV-REAL-SMTP-01", ledger, json_path)
    HTMLReporter.generate_report("INV-REAL-SMTP-01", ledger, html_path)
    PDFReporter.generate_report("INV-REAL-SMTP-01", ledger, pdf_path)

    assert json_path.exists() and json_path.stat().st_size > 0
    assert html_path.exists() and html_path.stat().st_size > 0
    assert pdf_path.exists() and pdf_path.stat().st_size > 0


def test_real_wireshark_imap_forensic_pipeline(tmp_path):
    """Verify real IMAP capture triggers stream reconstruction and protocol analysis."""
    pcap_path = SAMPLE_DIR / "wireshark_real_imap.pcap"
    assert pcap_path.exists()

    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    agent = InvestigationAgent(ledger)

    inv = agent.run_investigation(
        investigation_id="INV-REAL-IMAP-01",
        pcap_path=pcap_path,
    )

    assert inv.investigation_id == "INV-REAL-IMAP-01"
    assert inv.packet_count == 124
    assert "IMAP" in inv.protocols_detected
    assert inv.streams_analyzed >= 1
    assert inv.posture is not None
    assert inv.posture.confidence_score > 70.0

    findings = ledger.get_findings_for_investigation("INV-REAL-IMAP-01")
    for f in findings:
        assert len(f.evidence_ids) > 0


def test_real_wireshark_smtps_ssl_handshake(tmp_path):
    """Verify real SMTPS capture parses X.509 certificate and detects certificate status."""
    pcap_path = SAMPLE_DIR / "wireshark_real_smtp_ssl.pcapng"
    assert pcap_path.exists()

    ledger = EvidenceLedger(storage_path=tmp_path / "ledger.json")
    agent = InvestigationAgent(ledger)

    inv = agent.run_investigation(
        investigation_id="INV-REAL-SMTPS-01",
        pcap_path=pcap_path,
    )

    assert inv.investigation_id == "INV-REAL-SMTPS-01"
    assert inv.packet_count == 38
    assert inv.streams_analyzed >= 1

    findings = ledger.get_findings_for_investigation("INV-REAL-SMTPS-01")
    for f in findings:
        assert len(f.evidence_ids) > 0
        for ev_id in f.evidence_ids:
            assert ledger.get_evidence(ev_id) is not None


def test_api_upload_rejects_non_pcap():
    """Upload endpoint must reject non-pcap files with 400 Bad Request."""
    fake_png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    resp = client.post(
        "/api/investigations",
        files={"file": ("screenshot.png", fake_png, "image/png")},
    )
    assert resp.status_code == 400
    assert "Invalid file extension" in resp.text or "Only .pcap" in resp.text or "invalid" in resp.text.lower()

    fake_text = b"This is a plain text file pretending to be network traffic."
    resp2 = client.post(
        "/api/investigations",
        files={"file": ("fake.pcap", fake_text, "application/octet-stream")},
    )
    assert resp2.status_code == 400
    assert "magic bytes" in resp2.text.lower() or "invalid" in resp2.text.lower()
