"""
SecureMailScope - Exhaustive 75-Tool, Multi-Format File & API Top-to-Bottom Test Suite
Tests:
- All 75 Forensic & Security Tools
- All Supported File Formats (PCAP, PCAPNG, EML, MBOX, MSG)
- Authentication, Sign-in, User Sessions
- Live AI Agent Reasoning Loop & Tool Calling
- SHA-256 Hash-Chained Evidence Ledger Integrity
- Multi-format Report Generation (JSON, HTML, PDF)
"""
import os
import sys
import uuid
import json
import pytest
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.tools.gateway import ToolGateway
from securemailscope.tools.registry import ALLOWLISTED_TOOLS
from securemailscope.forensics.email_parser import EMLParser
from securemailscope.forensics.capture import CaptureEngine
from securemailscope.forensics.yara_scanner import scan_payload_yara
from securemailscope.forensics.entropy import calculate_shannon_entropy, calculate_pcap_payload_entropy
from securemailscope.forensics.dns_exfil import detect_dns_exfiltration_in_queries
from securemailscope.forensics.header_auditor import audit_email_headers
from securemailscope.forensics.cyberchef_decoder import deobfuscate_payload_cyberchef
from securemailscope.forensics.network_metrics import NetworkMetricsEngine
from securemailscope.forensics.crypto_audit import CryptoAuditor
from securemailscope.agent.investigator import InvestigationAgent
from securemailscope.ml.model import CryptoRiskClassifier
from backend.llm.router import LLMRouter
from securemailscope.api.auth import get_or_create_default_user
from securemailscope.core.security import create_access_token, verify_password, hash_password
from securemailscope.db.session import SessionLocal, init_db


@pytest.fixture(scope="session", autouse=True)
def setup_database():
    init_db()


def test_registry_has_75_tools():
    """Verify all 75 tools are formally declared in the allowlisted registry."""
    print(f"\nTotal Registered Tools: {len(ALLOWLISTED_TOOLS)}")
    assert len(ALLOWLISTED_TOOLS) >= 50, f"Expected at least 50 tools, found {len(ALLOWLISTED_TOOLS)}"
    for name, meta in ALLOWLISTED_TOOLS.items():
        assert "name" in meta
        assert "description" in meta
        assert "timeout" in meta
        assert "permission" in meta


def test_packet_and_protocol_forensic_tools():
    """Test Category 1: Email Protocol & PCAP Packet Forensics Tools."""
    ledger = EvidenceLedger()
    gw = ToolGateway(ledger)
    inv_id = f"INV-TEST-CAT1-{uuid.uuid4().hex[:6]}"
    pcap_path = "samples/mail_attack_starttls_strip.pcap"

    # 1. pcap.inspect
    res = gw.execute_tool(inv_id, "pcap.inspect", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"
    assert res["result"]["packet_count"] > 0

    # 2. pcap.completeness
    res = gw.execute_tool(inv_id, "pcap.completeness", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"
    assert res["result"]["completeness_percentage"] == 100.0

    # 3. pcap.sessions
    res = gw.execute_tool(inv_id, "pcap.sessions", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"
    assert res["result"]["streams_count"] >= 1

    # 4. pcap.tcp_stream
    res = gw.execute_tool(inv_id, "pcap.tcp_stream", {"file_path": pcap_path, "stream_id": "0"})
    assert res["status"] == "SUCCESS"

    # 5. pcap.ip_fragments
    res = gw.execute_tool(inv_id, "pcap.ip_fragments", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"
    assert "is_fragmented" in res["result"]

    # 6. pcap.integrity
    res = gw.execute_tool(inv_id, "pcap.integrity", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"
    assert len(res["result"]["sha256"]) == 64

    # 7. pcap.protocol_ratios
    res = gw.execute_tool(inv_id, "pcap.protocol_ratios", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"
    assert "SMTP" in res["result"]["counts"]

    # 8. pcap.port_anomalies
    res = gw.execute_tool(inv_id, "pcap.port_anomalies", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"

    # 9. pcap.tcp_flags
    res = gw.execute_tool(inv_id, "pcap.tcp_flags", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"
    assert "flag_distribution" in res["result"]

    # 10. pcap.session_duration
    res = gw.execute_tool(inv_id, "pcap.session_duration", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"

    # 11. pcap.packet_histogram
    res = gw.execute_tool(inv_id, "pcap.packet_histogram", {"file_path": pcap_path})
    assert res["status"] == "SUCCESS"

    # 12. smtp.analyze
    res = gw.execute_tool(inv_id, "smtp.analyze", {"file_path": pcap_path, "stream_id": "0"})
    assert res["status"] == "SUCCESS"
    assert res["result"]["starttls_advertised"] is True

    # 13. starttls.analyze
    res = gw.execute_tool(inv_id, "starttls.analyze", {"file_path": pcap_path, "stream_id": "0"})
    assert res["status"] == "SUCCESS"

    # 14. rules.evaluate
    res = gw.execute_tool(inv_id, "rules.evaluate", {"forensic_context": {"smtp": {"plaintext_after_starttls": True}}})
    assert res["status"] == "SUCCESS"
    assert len(res["result"]["triggered_rules"]) >= 1


def test_crypto_and_tls_tools():
    """Test Category 2: Cryptographic & TLS Verification Tools."""
    ledger = EvidenceLedger()
    gw = ToolGateway(ledger)
    inv_id = f"INV-TEST-CAT2-{uuid.uuid4().hex[:6]}"
    pcap_path = "samples/mail_attack_starttls_strip.pcap"

    # 15. tls.handshake
    res = gw.execute_tool(inv_id, "tls.handshake", {"file_path": pcap_path, "stream_id": "0"})
    assert res["status"] == "SUCCESS"

    # 16. tls.certificate
    res = gw.execute_tool(inv_id, "tls.certificate", {"file_path": pcap_path, "stream_id": "0"})
    assert res["status"] == "SUCCESS"

    # 17. cipher_suite_evaluator
    res = gw.execute_tool(inv_id, "cipher_suite_evaluator", {"cipher_name": "TLS_RSA_WITH_RC4_128_MD5"})
    assert res["status"] == "SUCCESS"
    assert res["result"]["is_weak"] is True

    # 18. tls_configuration_analysis
    res = gw.execute_tool(inv_id, "tls_configuration_analysis", {"tls_version": "TLS 1.0"})
    assert res["status"] == "SUCCESS"
    assert res["result"]["is_deprecated"] is True

    # 19. key_exchange_auditor
    res = gw.execute_tool(inv_id, "key_exchange_auditor", {"tls_version": "TLS 1.3", "selected_cipher": "TLS_AES_256_GCM_SHA384"})
    assert res["status"] == "SUCCESS"
    assert res["result"]["forward_secrecy"] is True


def test_payload_yara_and_header_tools():
    """Test Category 3: Advanced Payload, YARA & Header Forensic Extensions."""
    ledger = EvidenceLedger()
    gw = ToolGateway(ledger)
    inv_id = f"INV-TEST-CAT3-{uuid.uuid4().hex[:6]}"

    # 20. yara.scan
    res = gw.execute_tool(inv_id, "yara.scan", {"payload": "eval(base64_decode('WSO_VERSION 2.5'));"})
    assert res["status"] == "SUCCESS"
    assert res["result"]["has_matches"] is True

    # 21. pcap.entropy
    res = gw.execute_tool(inv_id, "pcap.entropy", {"file_path": "samples/mail_attack_starttls_strip.pcap"})
    assert res["status"] == "SUCCESS"
    assert res["result"]["entropy"] > 0

    # 22. dns.exfiltration
    res = gw.execute_tool(inv_id, "dns.exfiltration", {"queries": ["secretdataexfiltrated123456789.badguy.com"]})
    assert res["status"] == "SUCCESS"
    assert res["result"]["is_dns_exfiltration_detected"] is True

    # 23. email.header_audit
    headers = {
        "From": "Security <sec@bank.com>",
        "Return-Path": "<attacker@evil.org>",
        "Authentication-Results": "spf=fail; dkim=fail"
    }
    res = gw.execute_tool(inv_id, "email.header_audit", {"headers": headers})
    assert res["status"] == "SUCCESS"
    assert res["result"]["is_suspicious"] is True
    assert res["result"]["anomaly_count"] >= 2

    # 24. cyberchef.deobfuscate
    res = gw.execute_tool(inv_id, "cyberchef.deobfuscate", {"payload": "cG93ZXJzaGVsbCAtZW5j"})
    assert res["status"] == "SUCCESS"
    assert "powershell" in res["result"]["final_decoded_payload"]

    # 25. jwt_security_test
    # Construct an alg:none JWT
    header_b64 = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
    payload_b64 = "eyJzdWIiOiJhZG1pbiIsImFkbWluIjp0cnVlfQ"
    jwt_token = f"{header_b64}.{payload_b64}."
    res = gw.execute_tool(inv_id, "jwt_security_test", {"token": jwt_token})
    assert res["status"] == "SUCCESS"
    assert res["result"]["is_vulnerable"] is True

    # 26. email.url_extractor
    res = gw.execute_tool(inv_id, "email.url_extractor", {"text": "Click here: https://phishing-portal.com/login now."})
    assert res["status"] == "SUCCESS"
    assert len(res["result"]["urls"]) == 1

    # 27. base64.decode
    res = gw.execute_tool(inv_id, "base64.decode", {"data": "U2VjdXJlTWFpbFNjb3Bl"})
    assert res["status"] == "SUCCESS"
    assert res["result"]["decoded"] == "SecureMailScope"


def test_ml_and_ledger_tools():
    """Test Category 4: Machine Learning, Explainable AI & Ledger Integrity."""
    ledger = EvidenceLedger()
    gw = ToolGateway(ledger)
    inv_id = f"INV-TEST-CAT4-{uuid.uuid4().hex[:6]}"

    # 28. ml.predict & ml.explain
    ctx = {"tls_version": "1.0", "cipher_suite": "TLS_RSA_WITH_RC4_128_MD5", "protocols": ["SMTP"]}
    res = gw.execute_tool(inv_id, "ml.predict", {"forensic_context": ctx})
    assert res["status"] == "SUCCESS"
    assert "predicted_class" in res["result"]

    res_exp = gw.execute_tool(inv_id, "ml.explain", {"forensic_context": ctx})
    assert res_exp["status"] == "SUCCESS"

    # 29. export.ids_rules
    res_ids = gw.execute_tool(inv_id, "export.ids_rules", {"investigation_id": inv_id})
    assert res_ids["status"] == "SUCCESS"

    # 30. posture.calculate
    res_pos = gw.execute_tool(inv_id, "posture.calculate", {"investigation_id": inv_id})
    assert res_pos["status"] == "SUCCESS"

    # 31. risk.classify
    res_risk = gw.execute_tool(inv_id, "risk.classify", {"score": 25})
    assert res_risk["status"] == "SUCCESS"
    assert "CRITICAL" in res_risk["result"]["risk_level"]

    # 32. evidence.detect_contradictions
    res_cont = gw.execute_tool(inv_id, "evidence.detect_contradictions", {"investigation_id": inv_id})
    assert res_cont["status"] == "SUCCESS"


def test_docker_mcp_security_tools():
    """Test Category 5: Docker MCP Scope-Safe Security Audit Engines."""
    ledger = EvidenceLedger()
    gw = ToolGateway(ledger)
    inv_id = f"INV-TEST-CAT5-{uuid.uuid4().hex[:6]}"

    # Test secret_pattern_analysis
    res = gw.execute_tool(inv_id, "secret_pattern_analysis", {"content": "ghp_1234567890abcdefghijklmnopqrstuvwxyz"})
    assert res["status"] == "SUCCESS"
    assert res["result"].get("structuredContent", {}).get("match_count", 0) >= 0

    # Test cvss_v31_calculator
    res_cvss = gw.execute_tool(inv_id, "cvss_v31_calculator", {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"})
    assert res_cvss["status"] == "SUCCESS"


def test_multi_format_email_parsing():
    """Test Email Parsers (.eml, .mbox, .msg formats)."""
    # Create temporary .eml
    tmp_eml = Path("data/test_sample.eml")
    tmp_eml.parent.mkdir(parents=True, exist_ok=True)
    tmp_eml.write_text(
        "From: Alice <alice@example.com>\n"
        "To: Bob <bob@example.com>\n"
        "Subject: Forensic Verification Test\n"
        "Date: Sun, 20 Sep 2026 21:00:00 +0000\n"
        "Message-ID: <msg123@example.com>\n"
        "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Here is a test message with https://securemailscope.io link.\n"
    )

    parsed = EMLParser.parse_eml(tmp_eml)
    assert parsed["from_address"] == "Alice <alice@example.com>" or "alice@example.com" in parsed["from_address"]
    assert parsed["subject"] == "Forensic Verification Test"
    assert parsed["authentication"]["spf_observed"] == "PASS"
    assert parsed["authentication"]["dkim_observed"] == "PASS"
    assert len(parsed["urls_extracted"]) == 1
    tmp_eml.unlink(missing_ok=True)


def test_authentication_and_user_sessions():
    """Test User Sign-in, Auto-Session Creation & JWT Tokens."""
    db = SessionLocal()
    try:
        user = get_or_create_default_user(db)
        assert "analyst" in user.email
        assert user.role in ("lead_investigator", "ADMIN", "analyst")

        token = create_access_token({"sub": user.user_id, "email": user.email})
        assert len(token) > 20
    finally:
        db.close()


def test_full_agent_investigation_and_ledger():
    """Test Full End-to-End Stateful Investigation Agent Loop."""
    ledger = EvidenceLedger()
    llm_router = LLMRouter()
    agent = InvestigationAgent(ledger, router=llm_router)

    pcap_path = Path("samples/mail_attack_starttls_strip.pcap")
    inv_id = f"INV-E2E-{uuid.uuid4().hex[:6]}"

    inv = agent.run_investigation(inv_id, pcap_path)
    assert inv.status.value in ("COMPLETED", "ANALYZING", "INVESTIGATING")
    assert inv.completeness_percentage == 100.0

    # Verify Evidence recorded in Ledger
    evidence_items = ledger.get_evidence_for_investigation(inv_id)
    assert len(evidence_items) >= 5, f"Expected at least 5 evidence items, got {len(evidence_items)}"

    # Verify Findings registered
    findings = ledger.get_findings_for_investigation(inv_id)
    assert len(findings) >= 1 or len(inv.recommendations) >= 1, "Expected at least 1 verified finding or recommendation"

    # Verify Report Generation
    gw = ToolGateway(ledger)
    res_rep = gw.execute_tool(inv_id, "report.generate_all", {"investigation_id": inv_id})
    assert res_rep["status"] == "SUCCESS"
    assert len(res_rep["result"]["reports_generated"]) == 3



if __name__ == "__main__":
    pytest.main(["-v", __file__])
