"""
Unit tests for Adaptive Agent Investigation Branches
"""
from pathlib import Path
from securemailscope.core.config import SAMPLES_DIR
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.agent.investigator import InvestigationAgent


def test_agent_branch1_starttls_attack(tmp_path):
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger_b1.json")
    agent = InvestigationAgent(ledger)
    pcap = SAMPLES_DIR / "mail_attack_starttls_strip.pcap"

    inv = agent.run_investigation("INV-TEST-B1", pcap)
    assert inv.status.value == "COMPLETED"
    assert inv.posture.overall_posture_score < 70

    hyps = ledger.get_hypotheses_for_investigation("INV-TEST-B1")
    h1 = next((h for h in hyps if "STARTTLS" in h.title), None)
    assert h1 is not None
    assert h1.status.value == "CONFIRMED"

    findings = ledger.get_findings_for_investigation("INV-TEST-B1")
    assert any("STARTTLS" in f.title for f in findings)


def test_agent_branch1_partial_capture_inconclusive(tmp_path):
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger_b1_partial.json")
    agent = InvestigationAgent(ledger)
    pcap = SAMPLES_DIR / "mail_partial_capture_inconclusive.pcap"

    inv = agent.run_investigation("INV-TEST-PARTIAL", pcap)
    assert inv.status.value == "COMPLETED"
    assert inv.completeness_percentage < 60.0

    findings = ledger.get_findings_for_investigation("INV-TEST-PARTIAL")
    assert any("Inconclusive" in f.title for f in findings)


def test_agent_branch3_weak_crypto(tmp_path):
    ledger = EvidenceLedger(storage_path=tmp_path / "ledger_b3.json")
    agent = InvestigationAgent(ledger)
    pcap = SAMPLES_DIR / "mail_weak_crypto_tls10_rc4.pcap"

    inv = agent.run_investigation("INV-TEST-B3", pcap)
    assert inv.status.value == "COMPLETED"
    assert inv.posture.overall_posture_score <= 40
    assert inv.posture.risk_level in ("HIGH RISK", "CRITICAL RISK")

    findings = ledger.get_findings_for_investigation("INV-TEST-B3")
    assert any("Deprecated TLS" in f.title for f in findings)
    assert any("RC4" in f.title for f in findings)
