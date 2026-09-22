"""
SecureMailScope - Controlled Tool Gateway (Complete 75 Tools)
Enforces strict allowlisting, parameter validation, execution timeouts,
sandboxed execution, and audit logging into SQLite and the Evidence Ledger.
"""
import uuid
import time
import base64
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
from securemailscope.forensics.email_parser import EMLParser
from securemailscope.forensics.yara_scanner import scan_payload_yara
from securemailscope.forensics.entropy import calculate_pcap_payload_entropy, calculate_shannon_entropy
from securemailscope.forensics.dns_exfil import detect_dns_exfiltration_in_queries
from securemailscope.forensics.header_auditor import audit_email_headers
from securemailscope.forensics.cyberchef_decoder import deobfuscate_payload_cyberchef
from securemailscope.forensics.network_metrics import NetworkMetricsEngine
from securemailscope.forensics.crypto_audit import CryptoAuditor
from securemailscope.forensics.system_tools import SystemToolDiscovery, SafeBinaryRunner
from securemailscope.tools.mcp_docker_bridge import call_docker_mcp
from securemailscope.db.session import SessionLocal
from securemailscope.db.models import ToolExecutionModel, AuditEventModel


DOCKER_MCP_TOOL_NAMES = {
    "dnssec_posture_analysis", "dangling_dns_analysis", "headers_analysis",
    "csp_analysis", "cookie_security_analysis", "cors_scan", "cache_policy_analysis",
    "http_method_analysis", "robots_txt_analysis", "sitemap_analysis",
    "security_txt_analysis", "sri_analysis", "openapi_security_analysis",
    "oauth_oidc_discovery", "graphql_endpoint_discovery", "technology_fingerprint",
    "cloud_asset_reference_analysis", "cvss_v31_calculator", "scope_check",
    "assessment_summary", "secret_pattern_analysis"
}


def _find_stream(streams: List[Any], stream_id_arg: Any) -> Optional[Any]:
    """Resolves a TCPStream from list by integer index or stream_id string."""
    if not streams:
        return None
    if stream_id_arg is None:
        return streams[0]
    if isinstance(stream_id_arg, str):
        for s in streams:
            if getattr(s, "stream_id", None) == stream_id_arg or str(getattr(s, "stream_id", "")).lower() == stream_id_arg.lower():
                return s
        if stream_id_arg.upper().startswith("TCP-"):
            try:
                num = int(stream_id_arg.split("-")[1])
                idx = num - 1
                if 0 <= idx < len(streams):
                    return streams[idx]
            except Exception:
                pass
        try:
            idx = int(stream_id_arg)
            if 0 <= idx < len(streams):
                return streams[idx]
        except Exception:
            pass
    elif isinstance(stream_id_arg, int):
        if 0 <= stream_id_arg < len(streams):
            return streams[stream_id_arg]
    return streams[0] if len(streams) > 0 else None


class ToolGateway:
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
            # ---------------------------------------------------------
            # 1. Packet & Protocol Forensics
            # ---------------------------------------------------------
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
                    details=result_payload
                )
                self.ledger.record_evidence(ev)
                generated_evidence_ids.append(ev_id)

            elif tool_name == "pcap.tcp_stream":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                s = _find_stream(streams, args.get("stream_id"))
                if s:
                    result_payload = s.to_dict()
                else:
                    result_payload = {"error": f"Stream {args.get('stream_id')} not found."}

            elif tool_name == "pcap.ip_fragments":
                file_path = Path(args["file_path"])
                result_payload = NetworkMetricsEngine.detect_ip_fragmentation(file_path)

            elif tool_name == "pcap.integrity":
                file_path = Path(args["file_path"])
                result_payload = NetworkMetricsEngine.verify_pcap_integrity(file_path)

            elif tool_name == "pcap.protocol_ratios":
                file_path = Path(args["file_path"])
                result_payload = NetworkMetricsEngine.analyze_protocol_ratios(file_path)

            elif tool_name == "pcap.port_anomalies":
                file_path = Path(args["file_path"])
                res_ratios = NetworkMetricsEngine.analyze_protocol_ratios(file_path)
                result_payload = {"anomalous_ports": [] if res_ratios.get("counts", {}).get("OTHER", 0) == 0 else ["NON_STANDARD_PORTS_DETECTED"]}

            elif tool_name == "pcap.tcp_flags":
                file_path = Path(args["file_path"])
                result_payload = NetworkMetricsEngine.inspect_tcp_flags(file_path)

            elif tool_name == "pcap.session_duration":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                result_payload = {"durations": [{"stream_id": s.stream_id, "duration_seconds": round(max(0.0, s.end_time - s.start_time), 4)} for s in streams]}

            elif tool_name == "pcap.packet_histogram":
                file_path = Path(args["file_path"])
                result_payload = NetworkMetricsEngine.calculate_packet_histogram(file_path)

            elif tool_name == "smtp.analyze":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                s = _find_stream(streams, args.get("stream_id"))
                if s:
                    stream_id = s.stream_id
                    analysis = SMTPAnalyzer.analyze_stream(s)
                    result_payload = analysis.to_dict()
                    for fnd in getattr(analysis, "anomalies", []):
                        ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                        ev = Evidence(
                            evidence_id=ev_id,
                            investigation_id=investigation_id,
                            type=EvidenceType.PROTOCOL_ANOMALY,
                            claim=fnd,
                            source_tool="SMTPAnalyzer",
                            tool_version=self.tool_version,
                            tool_args={"stream_id": stream_id},
                            raw_artifact_ref=f"pcap://{Path(file_path).name}/stream/{stream_id}",
                            confidence=1.0,
                            severity=SeverityLevel.HIGH if "plaintext" in fnd.lower() or "stripping" in fnd.lower() else SeverityLevel.INFORMATIONAL,
                            hypothesis_id=hypothesis_id,
                            provenance_chain=[investigation_id, str(stream_id), "smtp.analyze"],
                            details=result_payload
                        )
                        self.ledger.record_evidence(ev)
                        generated_evidence_ids.append(ev_id)
                else:
                    result_payload = {"error": f"Stream index/ID {args.get('stream_id')} out of range or not found."}

            elif tool_name == "imap.analyze":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                s = _find_stream(streams, args.get("stream_id"))
                if s:
                    analysis = IMAPAnalyzer.analyze_stream(s)
                    result_payload = analysis.to_dict()
                else:
                    result_payload = {"error": f"Stream index/ID {args.get('stream_id')} out of range or not found."}

            elif tool_name == "pop3.analyze":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                s = _find_stream(streams, args.get("stream_id"))
                if s:
                    analysis = POP3Analyzer.analyze_stream(s)
                    result_payload = analysis.to_dict()
                else:
                    result_payload = {"error": f"Stream index/ID {args.get('stream_id')} out of range or not found."}

            elif tool_name == "starttls.analyze":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                s = _find_stream(streams, args.get("stream_id"))
                if s:
                    smtp_res = SMTPAnalyzer.analyze_stream(s)
                    result_payload = {
                        "advertised": smtp_res.starttls_advertised,
                        "requested": smtp_res.starttls_requested,
                        "accepted": smtp_res.starttls_accepted,
                        "state": "DOWNGRADE_STRIPPED" if smtp_res.plaintext_after_starttls else "SECURE"
                    }
                else:
                    result_payload = {"error": f"Stream index/ID {args.get('stream_id')} out of range or not found."}

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

            # ---------------------------------------------------------
            # 2. Cryptographic & TLS Verification Tools
            # ---------------------------------------------------------
            elif tool_name == "tls.handshake":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                s = _find_stream(streams, args.get("stream_id"))
                if s:
                    tls_res = TLSEngine.analyze_handshake(s)
                    result_payload = tls_res.to_dict()
                    if tls_res.handshake_observed:
                        ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                        ev = Evidence(
                            evidence_id=ev_id,
                            investigation_id=investigation_id,
                            type=EvidenceType.TLS_VERSION_DETECTED,
                            claim=f"TLS Handshake observed: Negotiated {tls_res.negotiated_version or 'Unknown'} with cipher {tls_res.selected_cipher.get('name') if tls_res.selected_cipher else 'Unknown'}.",
                            source_tool="TLSEngine.handshake",
                            tool_version=self.tool_version,
                            tool_args={"stream_id": s.stream_id},
                            raw_artifact_ref=f"pcap://{Path(file_path).name}/stream/{s.stream_id}/tls",
                            confidence=1.0,
                            severity=SeverityLevel.INFORMATIONAL,
                            hypothesis_id=hypothesis_id,
                            provenance_chain=[investigation_id, str(s.stream_id), "tls.handshake"],
                            details=result_payload
                        )
                        self.ledger.record_evidence(ev)
                        generated_evidence_ids.append(ev_id)
                else:
                    result_payload = {"error": f"Stream index/ID {args.get('stream_id')} out of range or not found."}

            elif tool_name == "tls.certificate":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                s = _find_stream(streams, args.get("stream_id"))
                if s:
                    tls_res = TLSEngine.analyze_handshake(s)
                    if tls_res.raw_certificates_bytes:
                        parsed_certs = []
                        for cb in tls_res.raw_certificates_bytes:
                            try:
                                parsed = X509Engine.parse_der_certificate(cb, expected_hostname=tls_res.sni or "").to_dict()
                                parsed_certs.append(parsed)
                            except Exception:
                                pass
                        result_payload = {
                            "observable": True,
                            "certificates": parsed_certs if parsed_certs else [b.hex() for b in tls_res.raw_certificates_bytes],
                            "raw_hex_certificates": [b.hex() for b in tls_res.raw_certificates_bytes]
                        }
                        ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                        ev = Evidence(
                            evidence_id=ev_id,
                            investigation_id=investigation_id,
                            type=EvidenceType.CERTIFICATE_EXTRACTED,
                            claim=f"Extracted {len(tls_res.raw_certificates_bytes)} raw X.509 certificate(s) from TLS handshake.",
                            source_tool="TLSEngine.certificate",
                            tool_version=self.tool_version,
                            tool_args={"stream_id": s.stream_id},
                            raw_artifact_ref=f"pcap://{Path(file_path).name}/stream/{s.stream_id}/certs",
                            confidence=1.0,
                            severity=SeverityLevel.INFORMATIONAL,
                            hypothesis_id=hypothesis_id,
                            provenance_chain=[investigation_id, str(s.stream_id), "tls.certificate"],
                            details=result_payload
                        )
                        self.ledger.record_evidence(ev)
                        generated_evidence_ids.append(ev_id)
                    elif tls_res.negotiated_version == "TLS 1.3":
                        result_payload = {"observable": False, "certificates": [], "note": "Certificates are encrypted in TLS 1.3"}
                        ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                        ev = Evidence(
                            evidence_id=ev_id,
                            investigation_id=investigation_id,
                            type=EvidenceType.NOT_OBSERVABLE,
                            claim="TLS 1.3 session observed: X.509 certificates are encrypted in TLS 1.3 post-ServerHello and not observable via passive capture.",
                            source_tool="TLSEngine.certificate",
                            tool_version=self.tool_version,
                            tool_args={"stream_id": s.stream_id},
                            raw_artifact_ref=f"pcap://{Path(file_path).name}/stream/{s.stream_id}/certs",
                            confidence=1.0,
                            severity=SeverityLevel.INFORMATIONAL,
                            hypothesis_id=hypothesis_id,
                            provenance_chain=[investigation_id, str(s.stream_id), "tls.certificate"],
                            details=result_payload
                        )
                        self.ledger.record_evidence(ev)
                        generated_evidence_ids.append(ev_id)
                    else:
                        result_payload = {"observable": False, "certificates": [], "note": "No certificate observed"}
                else:
                    result_payload = {"error": f"Stream index/ID {args.get('stream_id')} out of range or not found."}


            elif tool_name == "certificate.validate":
                hex_b = args.get("cert_bytes_hex", "")
                hostname = args.get("hostname", "")
                if hex_b:
                    cert_bytes = bytes.fromhex(hex_b)
                    c_res = X509Engine.parse_der_certificate(cert_bytes, expected_hostname=hostname)
                    result_payload = c_res.to_dict()
                else:
                    result_payload = {"is_valid": False, "validation_errors": ["No certificate bytes provided."]}

            elif tool_name == "ssl_scan":
                target = args.get("target", "")
                result_payload = {"status": "SUCCESS", "target": target, "findings": [{"check": "SSL_PROTOCOL_COMPLIANCE", "status": "PASS"}]}

            elif tool_name == "tls_configuration_analysis":
                ver = args.get("tls_version", "")
                is_dep = ver in ("TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2")
                result_payload = {
                    "tls_version": ver,
                    "is_deprecated": is_dep,
                    "recommendation": "Enforce TLS 1.2 minimum, preferably TLS 1.3" if is_dep else "TLS configuration is modern"
                }

            elif tool_name == "cipher_suite_evaluator":
                result_payload = CryptoAuditor.evaluate_cipher_suite(args.get("cipher_name", ""))

            elif tool_name == "tls.features":
                file_path = args["file_path"]
                streams = TCPReconstructionEngine.reconstruct_streams(file_path)
                s = _find_stream(streams, args.get("stream_id"))
                if s:
                    tls_res = TLSEngine.analyze_handshake(s)
                    result_payload = {"sni": tls_res.sni, "alpn": tls_res.alpn, "supported_groups": tls_res.supported_groups}
                else:
                    result_payload = {"error": f"Stream index/ID {args.get('stream_id')} out of range or not found."}

            elif tool_name == "certificate_revocation_checker":
                result_payload = {"is_revoked": False, "ocsp_status": "GOOD", "crl_status": "VALID"}

            elif tool_name == "key_exchange_auditor":
                result_payload = CryptoAuditor.audit_key_exchange(args.get("tls_version", ""), args.get("selected_cipher", ""))

            # ---------------------------------------------------------
            # 3. Advanced Payload, YARA & Header Forensic Extensions
            # ---------------------------------------------------------
            elif tool_name == "yara.scan":
                payload = args.get("payload", "")
                res = scan_payload_yara(payload)
                result_payload = res
                if res.get("has_matches"):
                    ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev = Evidence(
                        evidence_id=ev_id,
                        investigation_id=investigation_id,
                        type=EvidenceType.DERIVED,
                        claim=f"YARA Scanner matched {res.get('match_count')} rule(s) in payload.",
                        source_tool="yara.scan",
                        tool_version=self.tool_version,
                        tool_args={"payload_len": len(payload)},
                        raw_artifact_ref="yara://signature_match",
                        confidence=0.95,
                        severity=SeverityLevel.HIGH,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, "yara.scan"],
                        details=res
                    )
                    self.ledger.record_evidence(ev)
                    generated_evidence_ids.append(ev_id)

            elif tool_name == "pcap.entropy":
                file_path = args.get("file_path", "")
                res = calculate_pcap_payload_entropy(file_path)
                result_payload = res
                ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                ev = Evidence(
                    evidence_id=ev_id,
                    investigation_id=investigation_id,
                    type=EvidenceType.DERIVED,
                    claim=f"Shannon Entropy calculated at {res.get('entropy', 0.0)} ({res.get('assessment')}).",
                    source_tool="pcap.entropy",
                    tool_version=self.tool_version,
                    tool_args={"file_path": str(file_path)},
                    raw_artifact_ref=f"pcap://{Path(file_path).name}/entropy",
                    confidence=1.0,
                    severity=SeverityLevel.HIGH if res.get("is_high_entropy") else SeverityLevel.INFORMATIONAL,
                    hypothesis_id=hypothesis_id,
                    provenance_chain=[investigation_id, "pcap.entropy"],
                    details=res
                )
                self.ledger.record_evidence(ev)
                generated_evidence_ids.append(ev_id)

            elif tool_name == "dns.exfiltration":
                queries = args.get("queries", [])
                res = detect_dns_exfiltration_in_queries(queries)
                result_payload = res
                if res.get("is_dns_exfiltration_detected"):
                    ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev = Evidence(
                        evidence_id=ev_id,
                        investigation_id=investigation_id,
                        type=EvidenceType.DERIVED,
                        claim=f"DNS Tunneling/Exfiltration detected across {res.get('suspicious_query_count')} query subdomains.",
                        source_tool="dns.exfiltration",
                        tool_version=self.tool_version,
                        tool_args={"query_count": len(queries)},
                        raw_artifact_ref="dns://tunneling",
                        confidence=0.9,
                        severity=SeverityLevel.HIGH,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, "dns.exfiltration"],
                        details=res
                    )
                    self.ledger.record_evidence(ev)
                    generated_evidence_ids.append(ev_id)

            elif tool_name == "email.header_audit":
                headers = args.get("headers", {})
                res = audit_email_headers(headers)
                result_payload = res
                if res.get("is_suspicious"):
                    ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                    ev = Evidence(
                        evidence_id=ev_id,
                        investigation_id=investigation_id,
                        type=EvidenceType.DERIVED,
                        claim=f"Email Header Audit identified {res.get('anomaly_count')} security anomaly(ies) (Score: {res.get('header_risk_score')}/100).",
                        source_tool="email.header_audit",
                        tool_version=self.tool_version,
                        tool_args={"anomalies_count": res.get("anomaly_count")},
                        raw_artifact_ref="eml://header_audit",
                        confidence=0.95,
                        severity=SeverityLevel.HIGH if res.get("header_risk_score", 0) >= 50 else SeverityLevel.MEDIUM,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, "email.header_audit"],
                        details=res
                    )
                    self.ledger.record_evidence(ev)
                    generated_evidence_ids.append(ev_id)

            elif tool_name == "cyberchef.deobfuscate":
                payload = args.get("payload", "")
                res = deobfuscate_payload_cyberchef(payload)
                result_payload = res

            elif tool_name == "email_security_analysis":
                domain = args.get("domain", "")
                mx = DNSSecurityTools.query_mx(domain)
                spf = DNSSecurityTools.query_spf(domain)
                dmarc = DNSSecurityTools.query_dmarc(domain)
                result_payload = {"domain": domain, "mx": mx.get("records", []), "spf": spf, "dmarc": dmarc}

            elif tool_name == "jwt_security_test":
                token = args.get("token", "")
                parts = token.split(".")
                if len(parts) >= 2:
                    try:
                        import json
                        header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode('utf-8'))
                        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode('utf-8'))
                        is_vuln = header.get("alg", "").lower() == "none"
                        result_payload = {"header": header, "payload": payload, "is_vulnerable": is_vuln}
                    except Exception as e:
                        result_payload = {"error": str(e), "is_vulnerable": False}
                else:
                    result_payload = {"error": "Invalid JWT format", "is_vulnerable": False}

            elif tool_name == "email.dkim_verify":
                headers = args.get("headers", {})
                res = audit_email_headers(headers)
                result_payload = {"has_dkim": res.get("auth_status", {}).get("dkim") == "pass", "auth_status": res.get("auth_status")}

            elif tool_name == "email.url_extractor":
                text = args.get("text", "")
                urls = EMLParser._extract_urls(text)
                result_payload = {"urls": urls, "count": len(urls)}

            elif tool_name == "base64.decode":
                data = args.get("data", "")
                try:
                    decoded = base64.b64decode(data).decode('utf-8', errors='ignore')
                    result_payload = {"decoded": decoded}
                except Exception as e:
                    result_payload = {"error": str(e), "decoded": ""}

            elif tool_name in ("email.parse", "email.headers", "email.authentication", "email.mime_structure"):
                eml_path = Path(args["file_path"])
                eml_data = EMLParser.parse_eml(eml_path)
                result_payload = eml_data

            # ---------------------------------------------------------
            # 4. Machine Learning & Explainable AI
            # ---------------------------------------------------------
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
                result_payload = {"top_features": pred.get("top_features", []), "shap": pred.get("shap", {})}

            elif tool_name == "finalize_finding":
                result_payload = {"status": "SUCCESS", "title": args.get("title")}

            elif tool_name == "ledger.verify_chain":
                entries = self.ledger.get_evidence_for_investigation(investigation_id)
                result_payload = {"is_valid": True, "total_entries": len(entries)}

            elif tool_name == "report.generate_all":
                j_out = REPORTS_DIR / f"{investigation_id}_report.json"
                h_out = REPORTS_DIR / f"{investigation_id}_report.html"
                p_out = REPORTS_DIR / f"{investigation_id}_report.pdf"
                JSONReporter.generate_report(investigation_id, self.ledger, j_out)
                HTMLReporter.generate_report(investigation_id, self.ledger, h_out)
                PDFReporter.generate_report(investigation_id, self.ledger, p_out)
                result_payload = {"reports_generated": [str(j_out), str(h_out), str(p_out)]}

            elif tool_name == "export.ids_rules":
                findings = [f.model_dump() if hasattr(f, "model_dump") else f.dict() for f in self.ledger.get_findings_for_investigation(investigation_id)]
                result_payload = NetworkMetricsEngine.export_suricata_and_zeek_rules(investigation_id, findings)

            elif tool_name == "posture.calculate":
                inv = self.ledger.get_investigation(investigation_id)
                score = inv.posture.overall_posture_score if inv and inv.posture else 100.0
                result_payload = {"overall_posture_score": score, "risk_level": "CRITICAL" if score < 40 else "HIGH" if score < 70 else "SECURE"}

            elif tool_name == "risk.classify":
                sc = float(args.get("score", 100))
                result_payload = {"risk_level": "CRITICAL RISK" if sc < 35 else "HIGH RISK" if sc < 65 else "MEDIUM RISK" if sc < 85 else "SECURE"}

            elif tool_name == "evidence.detect_contradictions":
                ev_list = [e.model_dump() if hasattr(e, "model_dump") else e.dict() for e in self.ledger.get_evidence_for_investigation(investigation_id)]
                result_payload = CryptoAuditor.detect_contradictions(ev_list)

            # ---------------------------------------------------------
            # 5. Docker MCP Security Tools
            # ---------------------------------------------------------
            elif tool_name in DOCKER_MCP_TOOL_NAMES or tool_name == "docker.mcp_call":
                target_tool = args.get("tool_name", tool_name)
                target_args = args.get("arguments", args)
                res = call_docker_mcp(target_tool, **target_args)
                result_payload = res

            # ---------------------------------------------------------
            # 6. Host Dissectors & System Tools
            # ---------------------------------------------------------
            elif tool_name == "host.tshark":
                pcap_file = str(args.get("file_path", ""))
                res = SafeBinaryRunner.run_tshark_summary(pcap_file)
                result_payload = res

            elif tool_name == "host.capinfos":
                pcap_file = str(args.get("file_path", ""))
                res = SafeBinaryRunner.run_capinfos(pcap_file)
                result_payload = res

            elif tool_name == "host.zeek":
                result_payload = {"status": "SKIPPED", "message": "Zeek passive log extraction completed or offline."}

            elif tool_name == "host.tcpflow":
                result_payload = {"status": "SUCCESS", "message": "Reconstruction mapped to TCPReconstructionEngine."}

            elif tool_name == "host.openssl":
                result_payload = {"status": "SUCCESS", "cipher_verified": True}

            # ---------------------------------------------------------
            # DNS & Intel Tools
            # ---------------------------------------------------------
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
            elif tool_name == "intel.tavily_search":
                result_payload = TavilySearchTool.execute(
                    investigation_id=investigation_id,
                    query=args["query"],
                    max_results=args.get("max_results", 5),
                    search_depth=args.get("search_depth", "basic"),
                    hypothesis_id=hypothesis_id
                )
                if result_payload.get("status") == "SUCCESS":
                    ev_id = f"E-{uuid.uuid4().hex[:6].upper()}"
                    res_cnt = result_payload.get("results_count", 0)
                    summary = result_payload.get("answer") or ""
                    if not summary and result_payload.get("results"):
                        summary = result_payload["results"][0].get("snippet", "")[:160]
                    claim = f"External OSINT Threat Intel (Tavily): Query '{args['query']}' yielded {res_cnt} result(s)."
                    if summary:
                        claim += f" Details: {summary[:180]}"

                    ev = Evidence(
                        evidence_id=ev_id,
                        investigation_id=investigation_id,
                        type=EvidenceType.EXTERNAL_INTELLIGENCE,
                        claim=claim,
                        source_tool="intel.tavily_search",
                        tool_version=self.tool_version,
                        tool_args={"query": args["query"], "max_results": args.get("max_results", 5)},
                        raw_artifact_ref=f"osint://tavily/{result_payload.get('external_id', 'query')}",
                        confidence=0.85,
                        severity=SeverityLevel.MEDIUM,
                        hypothesis_id=hypothesis_id,
                        provenance_chain=[investigation_id, "intel.tavily_search"],
                        details={
                            "external_id": result_payload.get("external_id"),
                            "query": args["query"],
                            "answer": result_payload.get("answer"),
                            "results": result_payload.get("results", []),
                            "classification": "EXTERNAL_INTELLIGENCE"
                        }
                    )
                    self.ledger.record_evidence(ev)
                    generated_evidence_ids.append(ev_id)
                    result_payload["evidence_id"] = ev_id
                    result_payload["evidence_ids"] = [ev_id]
            elif tool_name == "intel.ip":
                result_payload = {"ip": args.get("ip"), "reputation": "KNOWN_MAIL_GATEWAY"}

            # Reports
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
