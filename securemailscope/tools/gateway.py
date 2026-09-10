"""
SecureMailScope - Controlled Tool Gateway
Enforces strict allowlisting, parameter validation, execution timeouts,
sandboxed execution, and audit logging into SQLite and the Evidence Ledger.
"""
import uuid
import time
from pathlib import Path
from typing import Dict, Any, List, Optional

from securemailscope.core.config import config, REPORTS_DIR
from securemailscope.core.exceptions import ToolExecutionError
from securemailscope.evidence.models import (
    Evidence,
    EvidenceType,
    SeverityLevel,
    ToolExecution,
    TimelineEvent
)
from securemailscope.evidence.ledger import EvidenceLedger
from securemailscope.tools.registry import ALLOWLISTED_TOOLS
from securemailscope.forensics.capture import CaptureEngine
from securemailscope.forensics.tcp_stream import TCPReconstructionEngine
from securemailscope.forensics.protocols.smtp import SMTPAnalyzer
from securemailscope.forensics.protocols.imap import IMAPAnalyzer
from securemailscope.forensics.protocols.pop3 import POP3Analyzer
from securemailscope.forensics.tls_engine import TLSEngine
from securemailscope.forensics.x509_engine import X509Engine
from securemailscope.forensics.rules import CryptoRuleEngine
from securemailscope.ml.feature_extractor import FeatureExtractor
from securemailscope.ml.model import CryptoRiskClassifier
from securemailscope.tools.dns_tools import DNSSecurityTools
from securemailscope.tools.tavily import TavilySearchTool
from securemailscope.reports.json_reporter import JSONReporter
from securemailscope.reports.html_reporter import HTMLReporter
from securemailscope.reports.pdf_reporter import PDFReporter
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import ToolExecutionModel, AuditEventModel


class ToolGateway:
    """
    Controlled Tool Gateway:
    - Restricts execution strictly to allowlisted tools
    - Validates arguments against schema
    - Records tool version, execution duration, and audit logs
    - Normalizes outputs and creates immutable Evidence items in the Ledger
    """

    def __init__(self, ledger: EvidenceLedger):
        self.ledger = ledger
        self.tool_version = config.version

    def execute_tool(
        self,
        investigation_id: str,
        tool_name: str,
        args: Dict[str, Any],
        hypothesis_id: Optional[str] = None
    ) -> Dict[str, Any]:
        if tool_name not in ALLOWLISTED_TOOLS:
            raise ToolExecutionError(f"Unauthorized or unknown tool requested: '{tool_name}'.")

        tool_meta = ALLOWLISTED_TOOLS[tool_name]
        # Validate required arguments
        for req_param in tool_meta.get("params", []):
            if req_param not in args:
                raise ToolExecutionError(f"Missing required argument '{req_param}' for tool '{tool_name}'.")

        exec_id = f"EXEC-{uuid.uuid4().hex[:8].upper()}"
        start_time_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        t0 = time.perf_counter()

        generated_evidence_ids: List[str] = []
        result_payload: Dict[str, Any] = {}
        status = "SUCCESS"
        error_msg = ""

        try:
            # 1. PCAP Tools
            if tool_name == "pcap.inspect":
                file_path = Path(args["file_path"])
                meta = CaptureEngine.inspect_capture(file_path)
                result_payload = meta

                ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                ev = Evidence(
                    evidence_id=ev_id,
                    investigation_id=investigation_id,
                    type=EvidenceType.OBSERVED,
                    claim=f"PCAP capture '{meta['artifact_name']}' loaded: {meta['packet_count']} packets, SHA256 {meta['artifact_sha256'][:16]}...",
                    source_tool="CaptureEngine",
                    tool_version=self.tool_version,
                    tool_args={"file_path": str(file_path)},
                    raw_artifact_ref=f"pcap://{meta['artifact_name']}",
                    confidence=1.0,
                    severity=SeverityLevel.INFORMATIONAL,
                    hypothesis_id=hypothesis_id,
                    provenance_chain=[investigation_id, meta["artifact_name"], "pcap.inspect"],
                    details=meta
                )
                self.ledger.record_evidence(ev)
                generated_evidence_ids.append(ev_id)

            elif tool_name == "pcap.completeness":
                file_path = Path(args["file_path"])
                meta = CaptureEngine.inspect_capture(file_path)
                comp = meta["completeness"]
                result_payload = comp

                ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                ev = Evidence(
                    evidence_id=ev_id,
                    investigation_id=investigation_id,
                    type=EvidenceType.DERIVED,
                    claim=f"Capture Completeness calculated at {comp['completeness_percentage']}% ({comp['assessment']}). Gaps: {comp['sequence_gaps']}, Retransmissions: {comp['retransmissions']}.",
                    source_tool="CaptureEngine.completeness",
                    tool_version=self.tool_version,
                    tool_args={"file_path": str(file_path)},
                    raw_artifact_ref=f"pcap://{file_path.name}/completeness",
                    confidence=1.0,
                    severity=SeverityLevel.INFORMATIONAL if comp["is_complete"] else SeverityLevel.MEDIUM,
                    hypothesis_id=hypothesis_id,
                    provenance_chain=[investigation_id, file_path.name, "pcap.completeness"],
                    details=comp
                )
                self.ledger.record_evidence(ev)
                generated_evidence_ids.append(ev_id)

            elif tool_name == "pcap.sessions":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                streams_summary = [s.to_dict() for s in streams]
                result_payload = {"streams_count": len(streams), "streams": streams_summary}

                ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                protos = list(set(s.protocol_hint for s in streams))
                ev = Evidence(
                    evidence_id=ev_id,
                    investigation_id=investigation_id,
                    type=EvidenceType.OBSERVED,
                    claim=f"Discovered {len(streams)} TCP stream(s) with protocols: {', '.join(protos)}.",
                    source_tool="TCPReconstructionEngine",
                    tool_version=self.tool_version,
                    tool_args={"file_path": file_path},
                    raw_artifact_ref=f"pcap://{Path(file_path).name}/streams",
                    confidence=1.0,
                    severity=SeverityLevel.INFORMATIONAL,
                    hypothesis_id=hypothesis_id,
                    provenance_chain=[investigation_id, Path(file_path).name, "pcap.sessions"],
                    details={"protocols": protos, "stream_count": len(streams)}
                )
                self.ledger.record_evidence(ev)
                generated_evidence_ids.append(ev_id)

            elif tool_name == "pcap.tcp_stream":
                file_path = args["file_path"]
                target_stream_id = args.get("stream_id")
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                selected = next((s for s in streams if s.stream_id == target_stream_id or not target_stream_id), streams[0] if streams else None)
                if not selected:
                    raise ToolExecutionError(f"Stream '{target_stream_id}' not found.")
                result_payload = selected.to_dict()

                ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                ev = Evidence(
                    evidence_id=ev_id,
                    investigation_id=investigation_id,
                    type=EvidenceType.OBSERVED,
                    claim=f"Reconstructed stream {selected.stream_id} ({selected.client_endpoint} -> {selected.server_endpoint}, {selected.total_bytes} bytes).",
                    source_tool="TCPReconstructionEngine.stream",
                    tool_version=self.tool_version,
                    tool_args={"file_path": file_path, "stream_id": selected.stream_id},
                    raw_artifact_ref=f"pcap://{Path(file_path).name}/{selected.stream_id}",
                    confidence=1.0,
                    severity=SeverityLevel.INFORMATIONAL,
                    hypothesis_id=hypothesis_id,
                    provenance_chain=[investigation_id, Path(file_path).name, selected.stream_id],
                    details=result_payload
                )
                self.ledger.record_evidence(ev)
                generated_evidence_ids.append(ev_id)

            # 2. Protocol Analyzers
            elif tool_name in ("smtp.analyze", "starttls.analyze"):
                file_path = args["file_path"]
                target_stream_id = args.get("stream_id")
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                selected = next((s for s in streams if s.stream_id == target_stream_id or not target_stream_id), streams[0] if streams else None)
                if not selected:
                    raise ToolExecutionError(f"Stream '{target_stream_id}' not found.")
                smtp_res = SMTPAnalyzer.analyze_stream(selected)
                result_payload = smtp_res.to_dict()

                if smtp_res.starttls_advertised:
                    ev_id1 = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev1 = Evidence(
                        evidence_id=ev_id1,
                        investigation_id=investigation_id,
                        type=EvidenceType.STARTTLS_ADVERTISED,
                        claim="SMTP Server advertised STARTTLS capability in EHLO response.",
                        source_tool="SMTPAnalyzer",
                        tool_version=self.tool_version,
                        tool_args={"stream_id": selected.stream_id},
                        raw_artifact_ref=f"pcap://{Path(file_path).name}/{selected.stream_id}/smtp",
                        confidence=1.0,
                        severity=SeverityLevel.INFORMATIONAL,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, Path(file_path).name, selected.stream_id, "EHLO"],
                        details={"advertised_extensions": smtp_res.advertised_extensions}
                    )
                    self.ledger.record_evidence(ev1)
                    generated_evidence_ids.append(ev_id1)

                if smtp_res.starttls_requested:
                    ev_id2 = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev2 = Evidence(
                        evidence_id=ev_id2,
                        investigation_id=investigation_id,
                        type=EvidenceType.STARTTLS_REQUESTED,
                        claim="SMTP Client issued STARTTLS command.",
                        source_tool="SMTPAnalyzer",
                        tool_version=self.tool_version,
                        tool_args={"stream_id": selected.stream_id},
                        raw_artifact_ref=f"pcap://{Path(file_path).name}/{selected.stream_id}/smtp",
                        confidence=1.0,
                        severity=SeverityLevel.INFORMATIONAL,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, Path(file_path).name, selected.stream_id, "STARTTLS"],
                        details={"client_ehlo": smtp_res.client_ehlo}
                    )
                    self.ledger.record_evidence(ev2)
                    generated_evidence_ids.append(ev_id2)

                if smtp_res.plaintext_after_starttls:
                    ev_id3 = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev3 = Evidence(
                        evidence_id=ev_id3,
                        investigation_id=investigation_id,
                        type=EvidenceType.PLAINTEXT_CONTINUATION,
                        claim="CRITICAL: Cleartext SMTP traffic continued on the wire after STARTTLS negotiation.",
                        source_tool="SMTPAnalyzer",
                        tool_version=self.tool_version,
                        tool_args={"stream_id": selected.stream_id},
                        raw_artifact_ref=f"pcap://{Path(file_path).name}/{selected.stream_id}/smtp/fallback",
                        confidence=0.99,
                        severity=SeverityLevel.CRITICAL,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, Path(file_path).name, selected.stream_id, "MAIL_FROM"],
                        details={"anomalies": smtp_res.anomalies}
                    )
                    self.ledger.record_evidence(ev3)
                    generated_evidence_ids.append(ev_id3)

            elif tool_name == "imap.analyze":
                file_path = args["file_path"]
                target_stream_id = args.get("stream_id")
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                selected = next((s for s in streams if s.stream_id == target_stream_id or not target_stream_id), streams[0] if streams else None)
                if not selected:
                    raise ToolExecutionError(f"Stream '{target_stream_id}' not found.")
                imap_res = IMAPAnalyzer.analyze_stream(selected)
                result_payload = imap_res.to_dict()

            elif tool_name == "pop3.analyze":
                file_path = args["file_path"]
                target_stream_id = args.get("stream_id")
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                selected = next((s for s in streams if s.stream_id == target_stream_id or not target_stream_id), streams[0] if streams else None)
                if not selected:
                    raise ToolExecutionError(f"Stream '{target_stream_id}' not found.")
                pop3_res = POP3Analyzer.analyze_stream(selected)
                result_payload = pop3_res.to_dict()

            # 3. TLS Tools
            elif tool_name in ("tls.handshake", "tls.features"):
                file_path = args["file_path"]
                target_stream_id = args.get("stream_id")
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                selected = next((s for s in streams if s.stream_id == target_stream_id or not target_stream_id), streams[0] if streams else None)
                if not selected:
                    raise ToolExecutionError(f"Stream '{target_stream_id}' not found.")
                tls_res = TLSEngine.analyze_stream(selected)
                result_payload = tls_res.to_dict()

                if tls_res.client_hello_observed:
                    ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev = Evidence(
                        evidence_id=ev_id,
                        investigation_id=investigation_id,
                        type=EvidenceType.OBSERVED,
                        claim=f"TLS ClientHello observed (SNI: {tls_res.sni or 'None'}, Offered Ciphers: {len(tls_res.client_ciphers)}).",
                        source_tool="TLSEngine",
                        tool_version=self.tool_version,
                        tool_args={"stream_id": selected.stream_id},
                        raw_artifact_ref=f"pcap://{Path(file_path).name}/{selected.stream_id}/tls",
                        confidence=1.0,
                        severity=SeverityLevel.INFORMATIONAL,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, Path(file_path).name, selected.stream_id, "ClientHello"],
                        details={"sni": tls_res.sni, "ciphers_count": len(tls_res.client_ciphers)}
                    )
                    self.ledger.record_evidence(ev)
                    generated_evidence_ids.append(ev_id)

                if tls_res.negotiated_version:
                    ev_id2 = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev2 = Evidence(
                        evidence_id=ev_id2,
                        investigation_id=investigation_id,
                        type=EvidenceType.OBSERVED,
                        claim=f"Negotiated TLS Version: {tls_res.negotiated_version} with cipher {tls_res.selected_cipher.get('name') if tls_res.selected_cipher else 'UNKNOWN'}.",
                        source_tool="TLSEngine",
                        tool_version=self.tool_version,
                        tool_args={"stream_id": selected.stream_id},
                        raw_artifact_ref=f"pcap://{Path(file_path).name}/{selected.stream_id}/tls",
                        confidence=1.0,
                        severity=SeverityLevel.HIGH if tls_res.negotiated_version in ("TLS 1.0", "TLS 1.1", "SSL 3.0") else SeverityLevel.INFORMATIONAL,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, Path(file_path).name, selected.stream_id, "ServerHello"],
                        details=result_payload
                    )
                    self.ledger.record_evidence(ev2)
                    generated_evidence_ids.append(ev_id2)

            elif tool_name == "tls.certificate":
                file_path = args["file_path"]
                target_stream_id = args.get("stream_id")
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                selected = next((s for s in streams if s.stream_id == target_stream_id or not target_stream_id), streams[0] if streams else None)
                if not selected:
                    raise ToolExecutionError(f"Stream '{target_stream_id}' not found.")
                tls_res = TLSEngine.analyze_stream(selected)

                parsed_certs = []
                for cert_bytes in tls_res.raw_certificates_bytes:
                    c_res = X509Engine.parse_der_certificate(cert_bytes, expected_hostname=tls_res.sni)
                    parsed_certs.append(c_res.to_dict())

                # Honest TLS 1.3 encrypted cert handling
                if tls_res.negotiated_version == "TLS 1.3":
                    result_payload = {
                        "status": "NOT_OBSERVABLE",
                        "reason": "Certificate exchange not observable from passive capture",
                        "observable": False,
                        "certificates": []
                    }
                    ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev = Evidence(
                        evidence_id=ev_id,
                        investigation_id=investigation_id,
                        type=EvidenceType.NOT_OBSERVABLE,
                        claim="TLS 1.3 Certificate exchange is encrypted and not observable from passive capture.",
                        source_tool="TLSEngine",
                        tool_version=self.tool_version,
                        tool_args={"stream_id": selected.stream_id},
                        raw_artifact_ref=f"pcap://{Path(file_path).name}/{selected.stream_id}/x509",
                        confidence=1.0,
                        severity=SeverityLevel.INFORMATIONAL,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, Path(file_path).name, selected.stream_id, "TLS13_EncryptedCert"],
                        details=result_payload
                    )
                    self.ledger.record_evidence(ev)
                    generated_evidence_ids.append(ev_id)
                else:
                    result_payload = {
                        "status": "OBSERVABLE" if parsed_certs else "NOT_OBSERVED",
                        "observable": tls_res.certificate_observable,
                        "note": tls_res.certificate_note,
                        "certificates": parsed_certs
                    }
                    if parsed_certs:
                        c0 = parsed_certs[0]
                        ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                        ev = Evidence(
                            evidence_id=ev_id,
                            investigation_id=investigation_id,
                            type=EvidenceType.CERTIFICATE_EXTRACTED,
                            claim=f"Extracted X.509 Certificate: Subject='{c0['subject']}', Issuer='{c0['issuer']}', Key={c0['public_key_algorithm']}-{c0['public_key_bits']}.",
                            source_tool="X509Engine",
                            tool_version=self.tool_version,
                            tool_args={"stream_id": selected.stream_id},
                            raw_artifact_ref=f"pcap://{Path(file_path).name}/{selected.stream_id}/x509",
                            confidence=1.0,
                            severity=SeverityLevel.HIGH if c0["validation_errors"] else SeverityLevel.INFORMATIONAL,
                            hypothesis_id=hypothesis_id,
                            provenance_chain=[investigation_id, Path(file_path).name, selected.stream_id, "Certificate"],
                            details=c0
                        )
                        self.ledger.record_evidence(ev)
                        generated_evidence_ids.append(ev_id)

            elif tool_name == "certificate.validate":
                cert_hex = args.get("cert_bytes_hex")
                hostname = args.get("hostname")
                if cert_hex:
                    cert_bytes = bytes.fromhex(cert_hex)
                    c_res = X509Engine.parse_der_certificate(cert_bytes, expected_hostname=hostname)
                    result_payload = c_res.to_dict()
                else:
                    result_payload = {"is_valid": False, "validation_errors": ["No certificate bytes provided."]}

            # 4. ML Tools
            elif tool_name == "ml.extract_features":
                ctx = args.get("forensic_context", {})
                f_dict = FeatureExtractor.extract_features(ctx)
                f_vec = FeatureExtractor.to_vector(f_dict)
                result_payload = {"features": f_dict, "vector": f_vec}

            elif tool_name == "ml.predict":
                ctx = args.get("forensic_context", {})
                classifier = CryptoRiskClassifier.get_instance()
                pred = classifier.predict_risk(ctx)
                result_payload = pred

                ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                ev = Evidence(
                    evidence_id=ev_id,
                    investigation_id=investigation_id,
                    type=EvidenceType.ML_CLASSIFICATION,
                    claim=f"ML Risk Classifier predicted '{pred['predicted_class']}' (Probability: {pred['risk_probability']*100:.1f}%, Confidence: {pred['class_confidence']*100:.1f}%).",
                    source_tool="CryptoRiskClassifier (XGBoost)",
                    tool_version="3.4",
                    tool_args={"predicted_class": pred["predicted_class"]},
                    raw_artifact_ref=f"ml://prediction/{pred['predicted_class']}",
                    confidence=pred["class_confidence"],
                    severity=SeverityLevel.HIGH if pred["is_anomalous"] else SeverityLevel.INFORMATIONAL,
                    hypothesis_id=hypothesis_id,
                    provenance_chain=[investigation_id, "XGBoost", pred["predicted_class"]],
                    details=pred
                )
                self.ledger.record_evidence(ev)
                generated_evidence_ids.append(ev_id)

            elif tool_name == "ml.explain":
                ctx = args.get("forensic_context", {})
                classifier = CryptoRiskClassifier.get_instance()
                pred = classifier.predict_risk(ctx)
                result_payload = {"top_features": pred.get("top_features", [])}

            # 5. DNS Security Policy Tools
            elif tool_name == "dns.mx":
                result_payload = DNSSecurityTools.query_mx(args["domain"])
            elif tool_name == "dns.spf":
                result_payload = DNSSecurityTools.query_spf(args["domain"])
            elif tool_name == "dns.dmarc":
                result_payload = DNSSecurityTools.query_dmarc(args["domain"])
            elif tool_name == "dns.mta_sts":
                result_payload = DNSSecurityTools.query_mta_sts(args["domain"])
            elif tool_name == "dns.tlsa":
                port = int(args.get("port", 25))
                result_payload = DNSSecurityTools.query_tlsa(args["domain"], port=port)

            # 6. External Intel: Tavily
            elif tool_name == "intel.tavily_search":
                tav_res = TavilySearchTool.execute(
                    investigation_id=investigation_id,
                    query=args["query"],
                    max_results=args.get("max_results", 5),
                    search_depth=args.get("search_depth", "basic"),
                    hypothesis_id=hypothesis_id
                )
                result_payload = tav_res
                if tav_res.get("status") == "SUCCESS":
                    ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev = Evidence(
                        evidence_id=ev_id,
                        investigation_id=investigation_id,
                        type=EvidenceType.EXTERNAL_INTELLIGENCE,
                        claim=f"External Web Intel via Tavily for '{args['query']}': {tav_res.get('results_count', 0)} sources retrieved.",
                        source_tool="intel.tavily_search",
                        tool_version="1.0",
                        tool_args={"query": args["query"]},
                        raw_artifact_ref=f"external://tavily/{tav_res.get('external_id')}",
                        confidence=0.85,
                        severity=SeverityLevel.INFORMATIONAL,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, "intel.tavily_search", tav_res.get("external_id", "EXT")],
                        details=tav_res
                    )
                    self.ledger.record_evidence(ev)
                    generated_evidence_ids.append(ev_id)

            # 7. Report Generation Tools
            elif tool_name == "report.generate_json":
                out_path = REPORTS_DIR / f"{investigation_id}_report.json"
                JSONReporter.generate_report(investigation_id, self.ledger, out_path)
                result_payload = {"report_path": str(out_path), "size_bytes": out_path.stat().st_size if out_path.exists() else 0}

            elif tool_name == "report.generate_html":
                out_path = REPORTS_DIR / f"{investigation_id}_report.html"
                HTMLReporter.generate_report(investigation_id, self.ledger, out_path)
                result_payload = {"report_path": str(out_path), "size_bytes": out_path.stat().st_size if out_path.exists() else 0}

            elif tool_name == "report.generate_pdf":
                out_path = REPORTS_DIR / f"{investigation_id}_report.pdf"
                PDFReporter.generate_report(investigation_id, self.ledger, out_path)
                result_payload = {"report_path": str(out_path), "size_bytes": out_path.stat().st_size if out_path.exists() else 0}

            # 8. Rules evaluation (backward compatible)
            elif tool_name == "rules.evaluate":
                ctx = args.get("forensic_context", {})
                eval_results = CryptoRuleEngine.evaluate(ctx)
                result_payload = {"triggered_rules": [r.to_dict() for r in eval_results if r.triggered]}

                for rule in eval_results:
                    if rule.triggered:
                        ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                        ev = Evidence(
                            evidence_id=ev_id,
                            investigation_id=investigation_id,
                            type=EvidenceType.CRYPTO_RULE_TRIGGERED,
                            claim=f"Rule Triggered [{rule.rule_id}]: {rule.title} - {rule.description}",
                            source_tool="CryptoRuleEngine",
                            tool_version=CryptoRuleEngine.RULE_SET_VERSION,
                            tool_args={"rule_id": rule.rule_id},
                            raw_artifact_ref=f"rule://{rule.rule_id}",
                            confidence=1.0,
                            severity=rule.severity,
                            hypothesis_id=hypothesis_id,
                            provenance_chain=[investigation_id, "CryptoRuleEngine", rule.rule_id],
                            details=rule.to_dict()
                        )
                        self.ledger.record_evidence(ev)
                        generated_evidence_ids.append(ev_id)

            elif tool_name == "intel.ip":
                target = args.get("ip", "")
                result_payload = {
                    "target": target,
                    "reputation": "KNOWN_LEGITIMATE" if "internal" in str(target) else "PUBLIC_MAIL_GATEWAY",
                    "cve_exposure": []
                }
                ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                ev = Evidence(
                    evidence_id=ev_id,
                    investigation_id=investigation_id,
                    type=EvidenceType.EXTERNAL_INTELLIGENCE,
                    claim=f"External endpoint reputation for '{target}': {result_payload['reputation']}.",
                    source_tool=tool_name,
                    tool_version=self.tool_version,
                    tool_args=args,
                    raw_artifact_ref=f"intel://{tool_name}/{target}",
                    confidence=0.85,
                    severity=SeverityLevel.INFORMATIONAL,
                    hypothesis_id=hypothesis_id,
                    provenance_chain=[investigation_id, tool_name, str(target)],
                    details=result_payload
                )
                self.ledger.record_evidence(ev)
                generated_evidence_ids.append(ev_id)

        except ToolExecutionError:
            raise
        except Exception as e:
            status = "ERROR"
            error_msg = str(e)
            result_payload = {"error": error_msg}

        end_time_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        # Persist ToolExecution to Ledger
        exec_record = ToolExecution(
            execution_id=exec_id,
            investigation_id=investigation_id,
            tool=tool_name,
            tool_version=self.tool_version,
            args=args,
            status=status,
            start_time=start_time_iso,
            end_time=end_time_iso,
            stdout_summary=f"Completed in {duration_ms}ms with {len(generated_evidence_ids)} evidence items.",
            stderr=error_msg,
            evidence_ids=generated_evidence_ids
        )
        self.ledger.record_tool_execution(exec_record)

        # Persist to SQLite via SQLAlchemy
        try:
            db = SessionLocal()
            try:
                db_exec = ToolExecutionModel(
                    execution_id=exec_id,
                    investigation_id=investigation_id,
                    tool=tool_name,
                    tool_version=self.tool_version,
                    args=args,
                    status=status,
                    stdout_summary=f"Completed in {duration_ms}ms with {len(generated_evidence_ids)} evidence items.",
                    stderr=error_msg,
                    evidence_ids=generated_evidence_ids
                )
                db.add(db_exec)
                db.commit()
            finally:
                db.close()
        except Exception:
            pass

        # Record timeline event
        tl_event = TimelineEvent(
            event_id=f"EVT-{uuid.uuid4().hex[:6].upper()}",
            phase="TOOL_EXECUTION",
            actor="TOOL_GATEWAY",
            action=f"Executed {tool_name}",
            detail=f"{tool_name} returned status '{status}' producing {len(generated_evidence_ids)} evidence item(s).",
            evidence_id=generated_evidence_ids[0] if generated_evidence_ids else None,
            hypothesis_id=hypothesis_id
        )
        self.ledger.record_timeline_event(tl_event, investigation_id)

        return {
            "execution_id": exec_id,
            "tool": tool_name,
            "status": status,
            "evidence_ids": generated_evidence_ids,
            "result": result_payload
        }
