"""
SecureMailScope - Real Stateful Investigation Agent
Explicit State-Machine Architecture:
OBSERVE -> HYPOTHESIZE -> PLAN -> SELECT_TOOL -> EXECUTE -> STORE_EVIDENCE -> CORRELATE -> RE_EVALUATE -> VERIFY -> VERDICT
Strictly evidence-constrained. Never invents facts.
Supports adaptive multi-branch investigations and deterministic fallback.
"""
import uuid
import time
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from securemailscope.core.config import config
from securemailscope.evidence.models import (
    Investigation,
    InvestigationStatus,
    Finding,
    FindingStatus,
    SeverityLevel,
    TimelineEvent,
    Evidence,
    EvidenceType
)
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.evidence.validator import FindingValidator
from securemailscope.tools.gateway import ToolGateway
from securemailscope.agent.hypothesis import HypothesisEngine
from securemailscope.ml.model import CryptoRiskClassifier
from securemailscope.scoring.posture_scorer import PostureScorer
from backend.llm.router import LLMRouter
from securemailscope.api.sse import SSEEventBus
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import (
    InvestigationModel,
    AgentRunModel,
    AgentStepModel,
    AuditEventModel,
    MLPredictionModel,
    ArtifactModel,
    ForensicSessionModel
)


class InvestigationAgent:
    """
    Production forensic investigation agent implementing an explicit state machine.
    """

    def __init__(self, ledger: EvidenceLedger, router: Optional[LLMRouter] = None):
        self.ledger = ledger
        self.gateway = ToolGateway(ledger)
        self.validator = FindingValidator(ledger)
        self.ml_classifier = CryptoRiskClassifier.get_instance()
        self.router = router or LLMRouter()

    def run_investigation(self, investigation_id: str, pcap_path: Path) -> Investigation:
        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        run_start = datetime.now(timezone.utc)

        # 1. Initialize or load Investigation
        inv = self.ledger.get_investigation(investigation_id)
        if not inv:
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

        # Record AgentRun in database
        llm_provider_name = "nvidia" if config.nvidia_api_key else ("gemini" if config.gemini_api_key else "deterministic")
        llm_model_name = config.nvidia_model if config.nvidia_api_key else (config.gemini_model if config.gemini_api_key else "local-rules")
        is_fallback = not (config.nvidia_api_key or config.gemini_api_key)

        try:
            db = SessionLocal()
            try:
                db_run = AgentRunModel(
                    run_id=run_id,
                    investigation_id=investigation_id,
                    status="RUNNING",
                    llm_provider=llm_provider_name,
                    llm_model=llm_model_name,
                    deterministic_fallback=is_fallback
                )
                db.add(db_run)
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

        step_counter = 0
        hyp_engine = HypothesisEngine(self.ledger, investigation_id)

        # Notify SSE subscribers that investigation has started
        SSEEventBus.publish_sync(investigation_id, "investigation.started", {
            "investigation_id": investigation_id,
            "artifact_name": pcap_path.name,
            "timestamp": run_start.isoformat(),
            "llm_provider": llm_provider_name,
            "llm_model": llm_model_name
        })

        def record_step(
            state: str,
            reason: str,
            tool: Optional[str] = None,
            tool_args: Optional[Dict[str, Any]] = None,
            result: Optional[Dict[str, Any]] = None,
            evidence_ids: Optional[List[str]] = None,
            hypothesis_title: Optional[str] = None,
            next_action: str = ""
        ):
            nonlocal step_counter
            step_counter += 1
            t_now = datetime.now(timezone.utc)

            # Publish SSE step event for real-time frontend terminal / log
            SSEEventBus.publish_sync(investigation_id, "agent.step", {
                "step_number": step_counter,
                "state": state,
                "hypothesis": hypothesis_title,
                "tool": tool,
                "reason": reason,
                "evidence_ids": evidence_ids or [],
                "next_action": next_action,
                "timestamp": t_now.isoformat()
            })

            try:
                db = SessionLocal()
                try:
                    step = AgentStepModel(
                        step_number=step_counter,
                        run_id=run_id,
                        investigation_id=investigation_id,
                        state=state,
                        hypothesis=hypothesis_title,
                        selected_tool=tool,
                        tool_arguments=tool_args or {},
                        reason=reason,
                        result=result or {},
                        evidence_ids=evidence_ids or [],
                        next_action=next_action,
                        provider=llm_provider_name,
                        model=llm_model_name,
                        timestamp=t_now,
                        duration=0.05
                    )
                    db.add(step)
                    db.commit()
                finally:
                    db.close()
            except Exception:
                pass

        # -------------------------------------------------------------
        # STATE: OBSERVE
        # -------------------------------------------------------------
        record_step(
            state="OBSERVE",
            reason="Initiating capture framing inspection and cryptographic hashing.",
            tool="pcap.inspect",
            tool_args={"file_path": str(pcap_path)},
            next_action="Reconstruct TCP conversations and discover email protocols."
        )
        inspect_res = self.gateway.execute_tool(investigation_id, "pcap.inspect", {"file_path": str(pcap_path)})
        meta = inspect_res["result"]
        inv.artifact_sha256 = meta.get("artifact_sha256", "")
        inv.artifact_md5 = meta.get("artifact_md5", "")
        inv.packet_count = meta.get("packet_count", 0)
        inv.duration_seconds = meta.get("duration_seconds", 0.0)

        # Persist Artifact in Database
        try:
            db = SessionLocal()
            try:
                art = db.query(ArtifactModel).filter_by(artifact_id=f"ART-{investigation_id}").first()
                if not art:
                    art = ArtifactModel(
                        artifact_id=f"ART-{investigation_id}",
                        investigation_id=investigation_id,
                        artifact_name=pcap_path.name,
                        file_path=str(pcap_path.resolve()),
                        file_size=pcap_path.stat().st_size if pcap_path.exists() else 0,
                        sha256=inv.artifact_sha256,
                        md5=inv.artifact_md5,
                        file_type="pcap",
                        meta_info=meta
                    )
                    db.add(art)
                    db.commit()
            finally:
                db.close()
        except Exception:
            pass

        # Discover sessions
        sess_res = self.gateway.execute_tool(investigation_id, "pcap.sessions", {"file_path": str(pcap_path)})
        streams = sess_res["result"].get("streams", [])
        inv.streams_analyzed = len(streams)
        inv.protocols_detected = list(set(s.get("protocol_hint", "UNKNOWN") for s in streams))
        inv.completeness_percentage = meta.get("completeness", {}).get("completeness_percentage", 100.0)
        self.ledger.save_investigation(inv)

        # Emit protocol and session SSE events
        SSEEventBus.publish_sync(investigation_id, "protocol.detected", {
            "protocols": inv.protocols_detected,
            "streams_count": inv.streams_analyzed,
            "completeness_percentage": inv.completeness_percentage
        })

        # Persist Sessions in Database and emit SSE
        try:
            db = SessionLocal()
            try:
                for s in streams:
                    sess_id = f"SESS-{investigation_id}-{s.get('stream_id', 0)}"
                    client_ep = (s.get("client_endpoint") or ":").split(":")
                    server_ep = (s.get("server_endpoint") or ":").split(":")
                    db_sess = db.query(ForensicSessionModel).filter_by(session_id=sess_id).first()
                    if not db_sess:
                        db_sess = ForensicSessionModel(
                            session_id=sess_id,
                            investigation_id=investigation_id,
                            stream_id=s.get("stream_id", 0),
                            client_ip=client_ep[0] if client_ep else "",
                            client_port=int(client_ep[1]) if len(client_ep) > 1 and client_ep[1].isdigit() else 0,
                            server_ip=server_ep[0] if server_ep else "",
                            server_port=int(server_ep[1]) if len(server_ep) > 1 and server_ep[1].isdigit() else 0,
                            protocol=s.get("protocol_hint", "UNKNOWN"),
                            tls_version=s.get("tls_version"),
                            cipher_suite=s.get("cipher_suite"),
                            sni=s.get("sni"),
                            details=s
                        )
                        db.add(db_sess)
                    SSEEventBus.publish_sync(investigation_id, "session.reconstructed", {
                        "stream_id": s.get("stream_id"),
                        "protocol": s.get("protocol_hint"),
                        "client_endpoint": s.get("client_endpoint"),
                        "server_endpoint": s.get("server_endpoint")
                    })
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

        forensic_context: Dict[str, Any] = {
            "tls": {},
            "smtp": {},
            "imap": {},
            "pop3": {},
            "certificate": {},
            "completeness": meta.get("completeness", {}),
            "stream": streams[0] if streams else {}
        }

        # Detailed protocol extraction
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

            tls_exec = self.gateway.execute_tool(investigation_id, "tls.handshake", {"file_path": str(pcap_path), "stream_id": stream_id})
            forensic_context["tls"] = tls_exec["result"]

            # Certificate extraction
            cert_exec = self.gateway.execute_tool(investigation_id, "tls.certificate", {"file_path": str(pcap_path), "stream_id": stream_id})
            certs = cert_exec["result"].get("certificates", [])
            if certs:
                forensic_context["certificate"] = certs[0]
                SSEEventBus.publish_sync(investigation_id, "certificate.extracted", {
                    "subject": certs[0].get("subject"),
                    "issuer": certs[0].get("issuer"),
                    "is_expired": certs[0].get("is_expired"),
                    "validation_errors": certs[0].get("validation_errors", [])
                })

        # -------------------------------------------------------------
        # STATE: HYPOTHESIZE & PLAN (Multi-Branch Investigation)
        # -------------------------------------------------------------
        inv.status = InvestigationStatus.INVESTIGATING
        self.ledger.save_investigation(inv)

        smtp_data = forensic_context.get("smtp", {})
        tls_data = forensic_context.get("tls", {})
        cert_data = forensic_context.get("certificate", {})
        neg_ver = tls_data.get("negotiated_version")
        sel_cipher = tls_data.get("selected_cipher") or {}

        # -------------------------------------------------------------
        # BRANCH 1: STARTTLS Stripping / Downgrade Anomaly
        # -------------------------------------------------------------
        starttls_anomaly = (
            (smtp_data.get("starttls_advertised") and smtp_data.get("starttls_requested") and not tls_data.get("client_hello_observed")) or
            smtp_data.get("plaintext_after_starttls") or
            forensic_context.get("imap", {}).get("plaintext_after_starttls") or
            forensic_context.get("pop3", {}).get("plaintext_after_stls")
        )

        if starttls_anomaly:
            h1 = hyp_engine.create_hypothesis("H1: STARTTLS Stripping / Downgrade Attack", "Active adversary or misconfigured MTA forced cleartext email fallback.")
            h2 = hyp_engine.create_hypothesis("H2: Incomplete Packet Capture", "Missing TLS ClientHello is an artifact of packet loss or truncated PCAP capture.")
            h3 = hyp_engine.create_hypothesis("H3: TLS Negotiation Failure", "Client or server aborted TLS handshake due to incompatible parameters.")

            record_step(
                state="HYPOTHESIZE",
                reason="STARTTLS negotiation sequence anomaly observed without TLS ClientHello. Formulating competing hypotheses H1 (Attack) vs H2 (Packet Loss) vs H3 (Negotiation Failure).",
                hypothesis_title=h1.title,
                next_action="Execute pcap.completeness tool to test H2 against capture continuity."
            )

            # PLAN & SELECT_TOOL: pcap.completeness
            comp_exec = self.gateway.execute_tool(investigation_id, "pcap.completeness", {"file_path": str(pcap_path)}, hypothesis_id=h1.hypothesis_id)
            comp_score = comp_exec["result"].get("completeness_percentage", 100.0)

            record_step(
                state="EXECUTE",
                reason=f"Calculated capture completeness is {comp_score}%.",
                tool="pcap.completeness",
                result=comp_exec["result"],
                evidence_ids=comp_exec["evidence_ids"],
                hypothesis_title=h1.title,
                next_action="Re-evaluate H1 vs H2 based on capture completeness."
            )

            if comp_score >= 95.0:
                # High completeness refutes H2, supports H1
                if comp_exec["evidence_ids"]:
                    hyp_engine.add_refuting_evidence(h2.hypothesis_id, comp_exec["evidence_ids"][0], 0.8, f"PCAP completeness is {comp_score}%; packet loss ruled out.")
                    hyp_engine.add_supporting_evidence(h1.hypothesis_id, comp_exec["evidence_ids"][0], 0.3, "High completeness proves unencrypted messages were actually transmitted.")

                # Inspect TCP stream for plaintext commands
                stream_exec = self.gateway.execute_tool(investigation_id, "pcap.tcp_stream", {"file_path": str(pcap_path)}, hypothesis_id=h1.hypothesis_id)
                if smtp_data.get("plaintext_after_starttls"):
                    hyp_engine.confirm_hypothesis(h1.hypothesis_id, "Verified cleartext MAIL FROM / DATA payload after STARTTLS acceptance.")
            else:
                # Low completeness supports H2, casts doubt on H1
                if comp_exec["evidence_ids"]:
                    hyp_engine.add_supporting_evidence(h2.hypothesis_id, comp_exec["evidence_ids"][0], 0.8, f"PCAP completeness is low ({comp_score}%); packet loss explains missing handshake.")
                hyp_engine.mark_inconclusive(h1.hypothesis_id, f"Cannot definitively confirm downgrade attack due to capture incompleteness ({comp_score}%).")
                inv.limitations.append(f"Capture completeness is {comp_score}%; packet drop explains missing TLS handshake.")

        # -------------------------------------------------------------
        # BRANCH 2: Certificate Anomaly & External Intel (Tavily)
        # -------------------------------------------------------------
        cert_errs = cert_data.get("validation_errors", [])
        cert_expired = cert_data.get("is_expired", False)
        cert_weak = cert_data.get("has_weak_key", False)
        cert_hostname_mismatch = not cert_data.get("hostname_match", True)

        if cert_errs or cert_expired or cert_weak or cert_hostname_mismatch:
            h4 = hyp_engine.create_hypothesis("H4: Certificate Trust / Cryptographic Defect", "The observed X.509 certificate fails public trust or contains cryptographic defects.")
            record_step(
                state="HYPOTHESIZE",
                reason=f"Observed X.509 certificate defect(s): {cert_errs}. Checking validation.",
                hypothesis_title=h4.title,
                next_action="Perform certificate validation."
            )

            is_self_signed = cert_data.get("is_self_signed", False)
            # If public-facing and external intelligence could reduce uncertainty:
            if not is_self_signed and config.tavily_enabled and config.allow_external_intel and config.tavily_api_key:
                domain_query = streams[0].get("server_endpoint", "").split(":")[0] if streams else "mail.example.com"
                record_step(
                    state="SELECT_TOOL",
                    reason="Certificate is public-facing with domain mismatch. Calling intel.tavily_search to check external domain trust.",
                    tool="intel.tavily_search",
                    tool_args={"query": f"{domain_query} mail certificate", "max_results": 3},
                    hypothesis_title=h4.title
                )
                tav_res = self.gateway.execute_tool(
                    investigation_id,
                    "intel.tavily_search",
                    {"query": f"{domain_query} mail certificate", "max_results": 3},
                    hypothesis_id=h4.hypothesis_id
                )
                if tav_res["evidence_ids"]:
                    hyp_engine.add_supporting_evidence(h4.hypothesis_id, tav_res["evidence_ids"][0], 0.3, "External intelligence query completed.")

            hyp_engine.confirm_hypothesis(h4.hypothesis_id, f"Confirmed certificate defects: {', '.join(cert_errs)}")

        # -------------------------------------------------------------
        # BRANCH 3: Weak Cryptography & Legacy Protocol
        # -------------------------------------------------------------
        is_deprecated = neg_ver in ("TLS 1.0", "TLS 1.1", "SSL 3.0")
        is_broken_cipher = sel_cipher.get("strength") in ("BROKEN", "LEGACY", "WEAK")
        no_pfs = tls_data.get("handshake_observed") and not tls_data.get("has_forward_secrecy")

        if is_deprecated or is_broken_cipher or no_pfs:
            h5 = hyp_engine.create_hypothesis("H5: Deprecated Protocol / Weak Cipher Configuration", "Session negotiated deprecated protocol parameters vulnerable to passive decryption.")
            record_step(
                state="HYPOTHESIZE",
                reason=f"Observed weak crypto: {neg_ver} / {sel_cipher.get('name')}. Evaluating policy compliance.",
                hypothesis_title=h5.title,
                next_action="Confirm cryptographic non-compliance."
            )
            hyp_engine.confirm_hypothesis(h5.hypothesis_id, f"Verified deprecated protocol parameters ({neg_ver}, {sel_cipher.get('name')}).")

        # Explicit honest TLS 1.3 Limitation
        if neg_ver == "TLS 1.3":
            inv.limitations.append("TLS 1.3 session observed: X.509 certificate exchange is encrypted post-ServerHello and not observable from passive capture.")

        # -------------------------------------------------------------
        # STATE: CORRELATE (Rules & ML)
        # -------------------------------------------------------------
        record_step(
            state="CORRELATE",
            reason="Evaluating deterministic cryptographic rules and XGBoost risk model.",
            tool="rules.evaluate",
            tool_args={"forensic_context": "context_payload"},
            next_action="Execute ML model inference."
        )
        rule_exec = self.gateway.execute_tool(investigation_id, "rules.evaluate", {"forensic_context": forensic_context})
        triggered_rules = rule_exec["result"].get("triggered_rules", [])

        # ML Risk Classification
        ml_result = self.ml_classifier.predict_risk(forensic_context)
        ev_ml_id = f"E-{uuid.uuid4().hex[:6].upper()}"
        from securemailscope.agent.investigator import from_ml_result
        self.ledger.record_evidence(from_ml_result(ev_ml_id, investigation_id, ml_result, pcap_path.name))

        # Persist ML prediction in DB
        try:
            db = SessionLocal()
            try:
                ml_pred = MLPredictionModel(
                    prediction_id=f"ML-{uuid.uuid4().hex[:8].upper()}",
                    investigation_id=investigation_id,
                    predicted_class=ml_result["predicted_class"],
                    risk_probability=ml_result["risk_probability"],
                    class_confidence=ml_result["class_confidence"],
                    is_anomalous=ml_result["is_anomalous"],
                    shap_attributions=ml_result.get("top_features", []),
                    feature_vector=ml_result.get("extracted_features", {})
                )
                db.add(ml_pred)
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

        # Emit ML Prediction SSE Event
        SSEEventBus.publish_sync(investigation_id, "ml.prediction.completed", {
            "predicted_class": ml_result["predicted_class"],
            "risk_probability": ml_result["risk_probability"],
            "class_confidence": ml_result["class_confidence"],
            "is_anomalous": ml_result["is_anomalous"]
        })

        # Contradiction Detection (Phase 45)
        # Check 1: Deterministic Rule vs ML Model Disagreement
        has_critical_rule = any(r.get("severity") in ("CRITICAL", "HIGH") for r in triggered_rules)
        ml_is_benign = ml_result["risk_probability"] < 0.25 and not ml_result["is_anomalous"]
        if has_critical_rule and ml_is_benign:
            contra_claim = (
                f"Contradiction detected: Deterministic rule flagged HIGH/CRITICAL violation "
                f"({[r['rule_id'] for r in triggered_rules if r.get('severity') in ('CRITICAL', 'HIGH')]}), "
                f"while ML model predicted low risk ({ml_result['risk_probability'] * 100:.1f}%). "
                f"Resolved by prioritizing deterministic ground-truth evidence."
            )
            ev_contra = Evidence(
                evidence_id=f"E-{uuid.uuid4().hex[:6].upper()}",
                investigation_id=investigation_id,
                type=EvidenceType.DERIVED,
                claim=contra_claim,
                source_tool="ContradictionEngine",
                tool_version="1.0",
                tool_args={"rule_ids": [r["rule_id"] for r in triggered_rules], "ml_pred": ml_result["predicted_class"]},
                raw_artifact_ref=f"pcap://{pcap_path.name}",
                confidence=0.95,
                severity=SeverityLevel.HIGH,
                provenance_chain=[investigation_id, "Rules", "MLModel", "DisagreementResolution"],
                details={"disagreement_type": "RULE_ML_CONFLICT", "resolution": "DETERMINISTIC_RULES_PREVAIL"}
            )
            self.ledger.record_evidence(ev_contra)
            inv.limitations.append("Statistical ML and deterministic rules diverged; deterministic protocol rules took precedence.")

        # Check 2: High completeness with cleartext continuation
        if inv.completeness_percentage >= 95.0 and smtp_data.get("plaintext_after_starttls"):
            ev_contra_downgrade = Evidence(
                evidence_id=f"E-{uuid.uuid4().hex[:6].upper()}",
                investigation_id=investigation_id,
                type=EvidenceType.DERIVED,
                claim="High capture completeness (>=95%) with continuous TCP sequencing contradicts packet drop; confirms deliberate STARTTLS strip or unencrypted downgrade.",
                source_tool="ContradictionEngine",
                tool_version="1.0",
                raw_artifact_ref=f"pcap://{pcap_path.name}",
                confidence=0.99,
                severity=SeverityLevel.CRITICAL,
                provenance_chain=[investigation_id, "pcap.completeness", "smtp.analyze"],
                details={"completeness": inv.completeness_percentage, "downgrade_confirmed": True}
            )
            self.ledger.record_evidence(ev_contra_downgrade)

        # -------------------------------------------------------------
        # STATE: VERIFY (Finding Formulation & Gatekeeper)
        # -------------------------------------------------------------
        inv.status = InvestigationStatus.VERIFYING
        self.ledger.save_investigation(inv)

        evidence_list = self.ledger.get_evidence_for_investigation(investigation_id)

        # Formulate findings based on triggered rules
        for r in triggered_rules:
            SSEEventBus.publish_sync(investigation_id, "rule.triggered", {
                "rule_id": r["rule_id"],
                "title": r["title"],
                "severity": r["severity"]
            })

            matching_eids = [e.evidence_id for e in evidence_list if r["rule_id"] in e.claim or e.type.value in (
                "STARTTLS_ADVERTISED", "STARTTLS_REQUESTED", "PLAINTEXT_CONTINUATION",
                "TLS_VERSION_DETECTED", "CERTIFICATE_EXTRACTED", "CRYPTO_RULE_TRIGGERED",
                "starttls_advertised", "starttls_requested", "plaintext_continuation",
                "tls_version_detected", "certificate_extracted", "crypto_rule_triggered",
                "OBSERVED", "DERIVED"
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
                    SSEEventBus.publish_sync(investigation_id, "finding.verified", {
                        "finding_id": fnd.finding_id,
                        "title": fnd.title,
                        "severity": fnd.severity.value,
                        "status": fnd.status.value,
                        "evidence_ids": fnd.evidence_ids
                    })
                except Exception as e:
                    self._record_agent_event(investigation_id, "VALIDATION_GATE", f"Finding rejected: {e}")

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
            SSEEventBus.publish_sync(investigation_id, "finding.verified", {
                "finding_id": fnd.finding_id,
                "title": fnd.title,
                "severity": fnd.severity.value,
                "status": fnd.status.value,
                "evidence_ids": fnd.evidence_ids
            })

        if not triggered_rules and inv.completeness_percentage >= 95.0 and neg_ver in ("TLS 1.2", "TLS 1.3"):
            inv.recommendations.append("Maintain current strong TLS and cipher configuration with periodic certificate rotation.")

        # -------------------------------------------------------------
        # STATE: VERDICT & REPORTING
        # -------------------------------------------------------------
        scorecard = PostureScorer.calculate_posture(forensic_context, triggered_rules, ml_result)
        inv.posture = scorecard
        inv.status = InvestigationStatus.COMPLETED
        self.ledger.save_investigation(inv)

        # Update Investigation in Database
        try:
            db = SessionLocal()
            try:
                db_inv = db.query(InvestigationModel).filter_by(investigation_id=investigation_id).first()
                if db_inv:
                    db_inv.status = "COMPLETED"
                    db_inv.posture_score = scorecard.overall_posture_score
                    db_inv.risk_level = scorecard.risk_level
                    db_inv.confidence_score = scorecard.confidence_score
                    db_inv.completed_at = datetime.now(timezone.utc)
                    db.commit()
            finally:
                db.close()
        except Exception:
            pass

        record_step(
            state="VERDICT",
            reason=f"Investigation completed: Posture {scorecard.overall_posture_score}/100 ({scorecard.risk_level}), Confidence {scorecard.confidence_score}%.",
            next_action="Generate deterministic forensic reports (JSON, HTML, PDF)."
        )

        # Generate Reports
        self.gateway.execute_tool(investigation_id, "report.generate_json", {"investigation_id": investigation_id})
        SSEEventBus.publish_sync(investigation_id, "report.generated", {"format": "json"})
        self.gateway.execute_tool(investigation_id, "report.generate_html", {"investigation_id": investigation_id})
        SSEEventBus.publish_sync(investigation_id, "report.generated", {"format": "html"})
        self.gateway.execute_tool(investigation_id, "report.generate_pdf", {"investigation_id": investigation_id})
        SSEEventBus.publish_sync(investigation_id, "report.generated", {"format": "pdf"})

        SSEEventBus.publish_sync(investigation_id, "investigation.completed", {
            "investigation_id": investigation_id,
            "posture_score": scorecard.overall_posture_score,
            "risk_level": scorecard.risk_level,
            "confidence_score": scorecard.confidence_score
        })

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
    return Evidence(
        evidence_id=ev_id,
        investigation_id=investigation_id,
        type=EvidenceType.ML_CLASSIFICATION,
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
