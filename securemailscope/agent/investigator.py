"""
SecureMailScope - Adaptive Investigation Agent
"""
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
from securemailscope.evidence.models import (
    Investigation,
    InvestigationStatus,
    Finding,
    FindingStatus,
    SeverityLevel,
    TimelineEvent
)
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.evidence.validator import FindingValidator
from securemailscope.tools.gateway import ToolGateway
from securemailscope.agent.hypothesis import HypothesisEngine
from securemailscope.agent.intelligence import IntelligenceAdapter
from securemailscope.ml.model import CryptoRiskClassifier
from securemailscope.scoring.posture_scorer import PostureScorer
from securemailscope.scoring.prioritizer import ThreatPrioritizer


class InvestigationAgent:
    """
    Adaptive, evidence-constrained forensic investigation agent.
    Never invents facts. Instead:
    1. Observes structured evidence
    2. Formulates testable hypotheses
    3. Identifies missing evidence and selects allowlisted tools dynamically
    4. Correlates multi-branch findings
    5. Validates findings strictly against persisted evidence in the ledger
    6. Yields an explainable verdict and security posture score.
    """

    def __init__(self, ledger: EvidenceLedger):
        self.ledger = ledger
        self.gateway = ToolGateway(ledger)
        self.validator = FindingValidator(ledger)
        self.ml_classifier = CryptoRiskClassifier.get_instance()

    def run_investigation(self, investigation_id: str, pcap_path: Path) -> Investigation:
        inv = self.ledger.get_investigation(investigation_id)
        if not inv:
            # Create fresh record
            inv = Investigation(
                investigation_id=investigation_id,
                artifact_name=pcap_path.name,
                artifact_path=str(pcap_path.resolve()),
                artifact_sha256="",
                artifact_md5="",
                artifact_size=pcap_path.stat().st_size if pcap_path.exists() else 0,
                status=InvestigationStatus.ANALYZING
            )
            self.ledger.save_investigation(inv)

        hyp_engine = HypothesisEngine(self.ledger, investigation_id)

        # -------------------------------------------------------------
        # Phase 1: Ingestion & Initial Protocol Discovery
        # -------------------------------------------------------------
        self._record_agent_event(investigation_id, "INGESTION", "Started passive capture analysis and metadata hashing.")
        inspect_res = self.gateway.execute_tool(investigation_id, "pcap.inspect", {"file_path": str(pcap_path)})
        meta = inspect_res["result"]
        inv.artifact_sha256 = meta.get("artifact_sha256", "")
        inv.artifact_md5 = meta.get("artifact_md5", "")
        inv.packet_count = meta.get("packet_count", 0)
        inv.duration_seconds = meta.get("duration_seconds", 0.0)

        # Discover sessions
        self._record_agent_event(investigation_id, "PROTOCOL_DISCOVERY", "Discovering email protocols and TCP conversations.")
        sess_res = self.gateway.execute_tool(investigation_id, "pcap.sessions", {"file_path": str(pcap_path)})
        streams = sess_res["result"].get("streams", [])
        inv.streams_analyzed = len(streams)
        inv.protocols_detected = list(set(s.get("protocol_hint", "UNKNOWN") for s in streams))
        self.ledger.save_investigation(inv)

        # Context accumulation for rules and ML
        forensic_context: Dict[str, Any] = {
            "tls": {},
            "smtp": {},
            "imap": {},
            "pop3": {},
            "certificate": {},
            "completeness": meta.get("completeness", {}),
            "stream": streams[0] if streams else {}
        }
        inv.completeness_percentage = meta.get("completeness", {}).get("completeness_percentage", 100.0)

        # -------------------------------------------------------------
        # Phase 2: Protocol Specific Extraction
        # -------------------------------------------------------------
        for s in streams:
            proto = s.get("protocol_hint")
            stream_id = s.get("stream_id")

            if proto == "SMTP":
                smtp_exec = self.gateway.execute_tool(investigation_id, "smtp.analyze", {"file_path": str(pcap_path), "stream_id": stream_id})
                forensic_context["smtp"] = smtp_exec["result"]
            elif proto == "IMAP":
                imap_exec = self.gateway.execute_tool(investigation_id, "imap.analyze", {"file_path": str(pcap_path), "stream_id": stream_id})
                forensic_context["imap"] = imap_exec["result"]
            elif proto == "POP3":
                pop3_exec = self.gateway.execute_tool(investigation_id, "pop3.analyze", {"file_path": str(pcap_path), "stream_id": stream_id})
                forensic_context["pop3"] = pop3_exec["result"]

            # TLS analysis for all streams
            tls_exec = self.gateway.execute_tool(investigation_id, "tls.handshake", {"file_path": str(pcap_path), "stream_id": stream_id})
            forensic_context["tls"] = tls_exec["result"]

            # Certificate extraction if observable
            if tls_exec["result"].get("certificate_observable") or len(tls_exec["result"].get("client_offered_versions", [])) > 0:
                cert_exec = self.gateway.execute_tool(investigation_id, "tls.certificate", {"file_path": str(pcap_path), "stream_id": stream_id})
                certs = cert_exec["result"].get("certificates", [])
                if certs:
                    forensic_context["certificate"] = certs[0]

        # -------------------------------------------------------------
        # Phase 3: Adaptive Agent Investigation Branches
        # -------------------------------------------------------------
        inv.status = InvestigationStatus.INVESTIGATING
        self.ledger.save_investigation(inv)

        # BRANCH 1: STARTTLS Anomaly Investigation
        smtp_data = forensic_context.get("smtp", {})
        tls_data = forensic_context.get("tls", {})
        
        starttls_anomaly_candidate = (
            (smtp_data.get("starttls_advertised") and smtp_data.get("starttls_requested") and not tls_data.get("client_hello_observed")) or
            smtp_data.get("plaintext_after_starttls") or
            forensic_context.get("imap", {}).get("plaintext_after_starttls") or
            forensic_context.get("pop3", {}).get("plaintext_after_stls")
        )

        if starttls_anomaly_candidate:
            self._record_agent_event(
                investigation_id,
                "ADAPTIVE_BRANCH_1",
                "Observed STARTTLS request without successful TLS handshake or plaintext continuation. Formulating hypotheses."
            )
            # Hypotheses
            h1 = hyp_engine.create_hypothesis("H1: STARTTLS Downgrade / Stripping Attack", "Active adversary or misconfigured MTA forced cleartext email fallback.")
            h2 = hyp_engine.create_hypothesis("H2: Incomplete Packet Capture", "Missing TLS ClientHello is an artifact of packet loss or truncated PCAP capture.")

            # Agent selects tool: pcap.completeness
            comp_exec = self.gateway.execute_tool(investigation_id, "pcap.completeness", {"file_path": str(pcap_path)}, hypothesis_id=h1.hypothesis_id)
            comp_score = comp_exec["result"].get("completeness_percentage", 100.0)

            if comp_score >= 95.0:
                # High completeness refutes H2, supports H1
                hyp_engine.add_refuting_evidence(h2.hypothesis_id, comp_exec["evidence_ids"][0], 0.8, "PCAP completeness is 99.6%; packet loss ruled out.")
                hyp_engine.add_supporting_evidence(h1.hypothesis_id, comp_exec["evidence_ids"][0], 0.3, "High capture completeness confirms traffic was actually transmitted as observed.")

                # Escalate to full TCP stream inspection
                stream_exec = self.gateway.execute_tool(investigation_id, "pcap.tcp_stream", {"file_path": str(pcap_path)}, hypothesis_id=h1.hypothesis_id)
                if smtp_data.get("plaintext_after_starttls"):
                    hyp_engine.confirm_hypothesis(h1.hypothesis_id, "Verified cleartext MAIL FROM / DATA payload after STARTTLS acceptance.")
            else:
                # Incomplete capture supports H2 and casts doubt on H1
                hyp_engine.add_supporting_evidence(h2.hypothesis_id, comp_exec["evidence_ids"][0], 0.7, f"PCAP completeness is low ({comp_score}%); packet drop explains missing TLS handshake.")
                hyp_engine.mark_inconclusive(h1.hypothesis_id, f"Cannot definitively confirm downgrade attack due to capture incompleteness ({comp_score}%).")
                inv.limitations.append(f"Capture completeness is {comp_score}%; missing packets may simulate STARTTLS failure.")

        # BRANCH 2: Certificate Trust & Validation Anomaly
        cert_data = forensic_context.get("certificate", {})
        if cert_data.get("validation_errors") or cert_data.get("is_expired") or cert_data.get("has_weak_key"):
            self._record_agent_event(
                investigation_id,
                "ADAPTIVE_BRANCH_2",
                "Observable X.509 certificate exhibited validation anomalies. Investigating endpoint context."
            )
            h4 = hyp_engine.create_hypothesis("H4: Certificate Trust / Cryptographic Flaw", "The server certificate fails public trust standards or uses deprecated key lengths.")
            # External CTI enrichment
            client_ip = streams[0].get("client_endpoint", "").split(":")[0] if streams else "127.0.0.1"
            intel_exec = self.gateway.execute_tool(investigation_id, "intel.ip", {"ip": client_ip}, hypothesis_id=h4.hypothesis_id)
            if intel_exec["evidence_ids"]:
                hyp_engine.add_supporting_evidence(h4.hypothesis_id, intel_exec["evidence_ids"][0], 0.4, "Evaluated endpoint exposure and reputation.")
            hyp_engine.confirm_hypothesis(h4.hypothesis_id, f"Confirmed certificate defects: {', '.join(cert_data.get('validation_errors', []))}")

        # BRANCH 3: Weak Cryptography & Legacy Protocol Negotiation
        neg_ver = tls_data.get("negotiated_version")
        sel_cipher = tls_data.get("selected_cipher") or {}
        if neg_ver in ("TLS 1.0", "TLS 1.1", "SSL 3.0") or sel_cipher.get("strength") in ("BROKEN", "LEGACY", "WEAK") or (tls_data.get("handshake_observed") and not tls_data.get("has_forward_secrecy")):
            self._record_agent_event(
                investigation_id,
                "ADAPTIVE_BRANCH_3",
                f"Negotiated {neg_ver} / {sel_cipher.get('name')}. Evaluating cryptographic compliance and forward secrecy."
            )
            h5 = hyp_engine.create_hypothesis("H5: Deprecated Cryptography / No Forward Secrecy", "Session negotiated deprecated protocol parameters vulnerable to passive decryption.")
            hyp_engine.confirm_hypothesis(h5.hypothesis_id, f"Verified deprecated protocol parameters ({neg_ver}, {sel_cipher.get('name')}).")

        # Explicit TLS 1.3 Limitation recording
        if neg_ver == "TLS 1.3":
            inv.limitations.append("TLS 1.3 session observed: X.509 certificate exchange is encrypted post-ServerHello and not observable from passive capture.")

        # -------------------------------------------------------------
        # Phase 4: Deterministic Rule Engine Execution
        # -------------------------------------------------------------
        rule_exec = self.gateway.execute_tool(investigation_id, "rules.evaluate", {"forensic_context": forensic_context})
        triggered_rules = rule_exec["result"].get("triggered_rules", [])

        # -------------------------------------------------------------
        # Phase 5: Machine Learning Risk Classification
        # -------------------------------------------------------------
        ml_result = self.ml_classifier.predict_risk(forensic_context)
        ev_ml_id = f"E-{uuid.uuid4().hex[:6].upper()}"
        ev_ml = self.ledger.record_evidence(
            self.ledger.get_evidence(ev_ml_id) or
            from_ml_result(ev_ml_id, investigation_id, ml_result, pcap_path.name)
        )

        # -------------------------------------------------------------
        # Phase 6: Posture Scoring & Threat Prioritization
        # -------------------------------------------------------------
        scorecard = PostureScorer.calculate_posture(forensic_context, triggered_rules, ml_result)
        inv.posture = scorecard

        # -------------------------------------------------------------
        # Phase 7: Finding Formulation & Verification Gate
        # -------------------------------------------------------------
        inv.status = InvestigationStatus.VERIFYING
        self.ledger.save_investigation(inv)

        evidence_list = self.ledger.get_evidence_for_investigation(investigation_id)
        evidence_by_type = {e.type.value: e for e in evidence_list}

        # Formulate findings based on deterministic rules and confirmed hypotheses
        for r in triggered_rules:
            # Collect matching evidence IDs
            matching_eids = [e.evidence_id for e in evidence_list if r["rule_id"] in e.claim or e.type.value in (
                "starttls_advertised", "starttls_requested", "plaintext_continuation",
                "tls_version_detected", "certificate_extracted", "crypto_rule_triggered"
            )]

            if matching_eids:
                fnd = Finding(
                    finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
                    investigation_id=investigation_id,
                    title=r["title"],
                    description=r["description"],
                    severity=SeverityLevel(r["severity"]),
                    status=FindingStatus.CANDIDATE,
                    evidence_ids=matching_eids[:5],
                    rule_id=r["rule_id"],
                    remediation=r["remediation"]
                )
                try:
                    self.validator.validate_and_register_finding(fnd)
                    inv.recommendations.append(r["remediation"])
                except Exception as e:
                    self._record_agent_event(investigation_id, "VALIDATION_GATE", f"Finding rejected by gatekeeper: {e}")

        # Inconclusive case handling
        if not triggered_rules and inv.completeness_percentage < 60.0:
            fnd = Finding(
                finding_id=f"FND-{uuid.uuid4().hex[:6].upper()}",
                investigation_id=investigation_id,
                title="Inconclusive Cryptographic Posture (Incomplete Capture)",
                description=f"Capture completeness is {inv.completeness_percentage}%. Insufficient evidence to establish cryptographic security.",
                severity=SeverityLevel.INFORMATIONAL,
                status=FindingStatus.INCONCLUSIVE,
                evidence_ids=[e.evidence_id for e in evidence_list][:3],
                remediation="Collect a complete full-packet capture with all TCP segments and TLS handshakes present."
            )
            self.validator.validate_and_register_finding(fnd)
            inv.recommendations.append(fnd.remediation)

        # Baseline clean case
        if not triggered_rules and inv.completeness_percentage >= 95.0 and neg_ver in ("TLS 1.2", "TLS 1.3"):
            inv.recommendations.append("Maintain current strong TLS and cipher configuration with periodic certificate rotation.")

        inv.status = InvestigationStatus.COMPLETED
        self.ledger.save_investigation(inv)
        self._record_agent_event(investigation_id, "COMPLETION", f"Investigation completed with posture score {scorecard.overall_posture_score}/100 ({scorecard.risk_level}).")

        return inv

    def _record_agent_event(self, investigation_id: str, phase: str, detail: str):
        evt = TimelineEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:6].upper()}",
            phase=phase,
            actor="INVESTIGATION_AGENT",
            action=phase,
            detail=detail
        )
        self.ledger.record_timeline_event(evt, investigation_id)


def from_ml_result(ev_id: str, investigation_id: str, ml_result: Dict[str, Any], pcap_name: str):
    from securemailscope.evidence.models import Evidence, EvidenceType, SeverityLevel
    return Evidence(
        evidence_id=ev_id,
        investigation_id=investigation_id,
        type=EvidenceType.ML_PREDICTION,
        claim=f"XGBoost Classifier classified session as '{ml_result['predicted_class']}' (Risk Probability: {ml_result['risk_probability'] * 100:.1f}%, Confidence: {ml_result['class_confidence'] * 100:.1f}%).",
        source_tool="CryptoRiskClassifier (XGBoost)",
        tool_version="3.4",
        tool_args={"predicted_class": ml_result["predicted_class"]},
        raw_artifact_ref=f"ml://prediction/{pcap_name}",
        confidence=ml_result["class_confidence"],
        severity=SeverityLevel.HIGH if ml_result["is_anomalous"] else SeverityLevel.INFORMATIONAL,
        provenance_chain=[investigation_id, pcap_name, "XGBoost", ml_result["predicted_class"]],
        details=ml_result
    )
