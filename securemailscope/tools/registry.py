"""
SecureMailScope - Allowlisted Tool Registry
Defines the strict whitelist of permissible tools, input schemas,
output schemas, permissions, and execution timeouts.
"""
from typing import Dict, Any

ALLOWLISTED_TOOLS: Dict[str, Dict[str, Any]] = {
    "pcap.inspect": {
        "name": "pcap.inspect",
        "description": "Inspects PCAP framing, extracts packet count, timestamps, SHA-256 and MD5 hashes.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"artifact_name": "string", "packet_count": "integer", "duration_seconds": "number"},
        "permission": "read_artifact",
        "timeout": 30.0,
        "params": ["file_path"]
    },
    "pcap.sessions": {
        "name": "pcap.sessions",
        "description": "Discovers email protocol sessions (SMTP, IMAP, POP3) across reconstructed TCP streams.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"streams_count": "integer", "streams": "array"},
        "permission": "read_artifact",
        "timeout": 30.0,
        "params": ["file_path"]
    },
    "pcap.tcp_stream": {
        "name": "pcap.tcp_stream",
        "description": "Reconstructs directional payload flows and packet sequence timeline for a specific TCP stream.",
        "input_schema": {"file_path": "string", "stream_id": "string"},
        "output_schema": {"stream_id": "string", "client_endpoint": "string", "server_endpoint": "string"},
        "permission": "read_artifact",
        "timeout": 30.0,
        "params": ["file_path"]
    },
    "pcap.completeness": {
        "name": "pcap.completeness",
        "description": "Calculates capture completeness score, sequence gaps, retransmissions, and truncation.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"completeness_percentage": "number", "is_complete": "boolean", "assessment": "string"},
        "permission": "read_artifact",
        "timeout": 30.0,
        "params": ["file_path"]
    },
    "smtp.analyze": {
        "name": "smtp.analyze",
        "description": "Evaluates SMTP state machine, STARTTLS negotiation, cleartext commands, and stripping anomalies.",
        "input_schema": {"file_path": "string", "stream_id": "string"},
        "output_schema": {"starttls_advertised": "boolean", "plaintext_after_starttls": "boolean"},
        "permission": "read_artifact",
        "timeout": 20.0,
        "params": ["file_path", "stream_id"]
    },
    "imap.analyze": {
        "name": "imap.analyze",
        "description": "Evaluates IMAP state machine, STARTTLS capabilities, OK responses, and cleartext authentication.",
        "input_schema": {"file_path": "string", "stream_id": "string"},
        "output_schema": {"starttls_advertised": "boolean", "plaintext_after_starttls": "boolean"},
        "permission": "read_artifact",
        "timeout": 20.0,
        "params": ["file_path", "stream_id"]
    },
    "pop3.analyze": {
        "name": "pop3.analyze",
        "description": "Evaluates POP3 state machine, STLS capability, +OK transitions, and cleartext credentials.",
        "input_schema": {"file_path": "string", "stream_id": "string"},
        "output_schema": {"stls_advertised": "boolean", "plaintext_after_stls": "boolean"},
        "permission": "read_artifact",
        "timeout": 20.0,
        "params": ["file_path", "stream_id"]
    },
    "starttls.analyze": {
        "name": "starttls.analyze",
        "description": "Comprehensive evaluation of STARTTLS negotiation state across all email protocols.",
        "input_schema": {"file_path": "string", "stream_id": "string"},
        "output_schema": {"advertised": "boolean", "requested": "boolean", "accepted": "boolean", "state": "string"},
        "permission": "read_artifact",
        "timeout": 20.0,
        "params": ["file_path", "stream_id"]
    },
    "tls.handshake": {
        "name": "tls.handshake",
        "description": "Parses TLS ClientHello/ServerHello, cipher suites, version negotiation, and key exchange.",
        "input_schema": {"file_path": "string", "stream_id": "string"},
        "output_schema": {"negotiated_version": "string", "selected_cipher": "object", "has_forward_secrecy": "boolean"},
        "permission": "read_artifact",
        "timeout": 20.0,
        "params": ["file_path", "stream_id"]
    },
    "tls.features": {
        "name": "tls.features",
        "description": "Extracts TLS extensions, ALPN, SNI, supported groups, and handshake completeness indicators.",
        "input_schema": {"file_path": "string", "stream_id": "string"},
        "output_schema": {"sni": "string", "alpn": "array", "supported_groups": "array"},
        "permission": "read_artifact",
        "timeout": 20.0,
        "params": ["file_path", "stream_id"]
    },
    "tls.certificate": {
        "name": "tls.certificate",
        "description": "Extracts observable X.509 certificates (TLS <= 1.2) or returns honest NOT_OBSERVABLE for TLS 1.3.",
        "input_schema": {"file_path": "string", "stream_id": "string"},
        "output_schema": {"observable": "boolean", "certificates": "array", "note": "string"},
        "permission": "read_artifact",
        "timeout": 20.0,
        "params": ["file_path", "stream_id"]
    },
    "certificate.validate": {
        "name": "certificate.validate",
        "description": "Performs cryptographic verification of X.509 certificate against trust store, validity, and SAN.",
        "input_schema": {"cert_bytes_hex": "string", "hostname": "string"},
        "output_schema": {"is_valid": "boolean", "validation_errors": "array"},
        "permission": "crypto_verify",
        "timeout": 15.0,
        "params": ["cert_bytes_hex", "hostname"]
    },
    "ml.extract_features": {
        "name": "ml.extract_features",
        "description": "Extracts normalized numeric and boolean feature vectors from forensic context.",
        "input_schema": {"forensic_context": "object"},
        "output_schema": {"features": "object", "vector": "array"},
        "permission": "ml_inference",
        "timeout": 10.0,
        "params": ["forensic_context"]
    },
    "ml.predict": {
        "name": "ml.predict",
        "description": "Runs XGBoost classifier to identify multi-feature cryptographic risk patterns.",
        "input_schema": {"forensic_context": "object"},
        "output_schema": {"predicted_class": "string", "risk_probability": "number", "confidence": "number"},
        "permission": "ml_inference",
        "timeout": 10.0,
        "params": ["forensic_context"]
    },
    "ml.explain": {
        "name": "ml.explain",
        "description": "Calculates explainable feature attributions and SHAP contributions for ML classification.",
        "input_schema": {"forensic_context": "object"},
        "output_schema": {"top_features": "array"},
        "permission": "ml_inference",
        "timeout": 10.0,
        "params": ["forensic_context"]
    },
    "dns.mx": {
        "name": "dns.mx",
        "description": "Resolves public Mail Exchange (MX) DNS records for domain.",
        "input_schema": {"domain": "string"},
        "output_schema": {"domain": "string", "records": "array", "has_mx": "boolean"},
        "permission": "external_network",
        "timeout": 10.0,
        "params": ["domain"]
    },
    "dns.spf": {
        "name": "dns.spf",
        "description": "Resolves and evaluates Sender Policy Framework (SPF) DNS TXT record for domain.",
        "input_schema": {"domain": "string"},
        "output_schema": {"domain": "string", "has_spf": "boolean", "spf_record": "string"},
        "permission": "external_network",
        "timeout": 10.0,
        "params": ["domain"]
    },
    "dns.dmarc": {
        "name": "dns.dmarc",
        "description": "Resolves and evaluates DMARC TXT record for domain.",
        "input_schema": {"domain": "string"},
        "output_schema": {"domain": "string", "has_dmarc": "boolean", "dmarc_record": "string"},
        "permission": "external_network",
        "timeout": 10.0,
        "params": ["domain"]
    },
    "dns.mta_sts": {
        "name": "dns.mta_sts",
        "description": "Checks MTA-STS TXT record (_mta-sts) to verify inbound TLS enforcement policy.",
        "input_schema": {"domain": "string"},
        "output_schema": {"domain": "string", "has_mta_sts": "boolean"},
        "permission": "external_network",
        "timeout": 10.0,
        "params": ["domain"]
    },
    "dns.tlsa": {
        "name": "dns.tlsa",
        "description": "Queries DANE TLSA DNS record for port 25/SMTP certificate pinning.",
        "input_schema": {"domain": "string", "port": "integer"},
        "output_schema": {"domain": "string", "has_dane_tlsa": "boolean"},
        "permission": "external_network",
        "timeout": 10.0,
        "params": ["domain"]
    },
    "intel.tavily_search": {
        "name": "intel.tavily_search",
        "description": "Executes external web intelligence search via Tavily to reduce uncertainty on observable entities.",
        "input_schema": {"query": "string", "max_results": "integer", "search_depth": "string"},
        "output_schema": {"status": "string", "results": "array", "evidence_classification": "string"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["query"]
    },
    "report.generate_json": {
        "name": "report.generate_json",
        "description": "Generates immutable machine-readable JSON forensic dossier.",
        "input_schema": {"investigation_id": "string"},
        "output_schema": {"report_path": "string", "size_bytes": "integer"},
        "permission": "generate_report",
        "timeout": 15.0,
        "params": ["investigation_id"]
    },
    "report.generate_html": {
        "name": "report.generate_html",
        "description": "Generates standalone publication-ready HTML forensic report.",
        "input_schema": {"investigation_id": "string"},
        "output_schema": {"report_path": "string", "size_bytes": "integer"},
        "permission": "generate_report",
        "timeout": 15.0,
        "params": ["investigation_id"]
    },
    "report.generate_pdf": {
        "name": "report.generate_pdf",
        "description": "Generates audit-grade PDF forensic report via ReportLab.",
        "input_schema": {"investigation_id": "string"},
        "output_schema": {"report_path": "string", "size_bytes": "integer"},
        "permission": "generate_report",
        "timeout": 20.0,
        "params": ["investigation_id"]
    },
    # Backwards-compatible aliases
    "rules.evaluate": {
        "name": "rules.evaluate",
        "description": "Executes deterministic cryptographic rules across extracted forensic context.",
        "input_schema": {"forensic_context": "object"},
        "output_schema": {"triggered_rules": "array"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["forensic_context"]
    },
    "intel.ip": {
        "name": "intel.ip",
        "description": "Enriches endpoint IP reputation.",
        "input_schema": {"ip": "string"},
        "output_schema": {"reputation": "string"},
        "permission": "external_intel",
        "timeout": 10.0,
        "params": ["ip"]
    }
}
