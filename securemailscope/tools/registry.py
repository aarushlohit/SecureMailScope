"""
SecureMailScope - Allowlisted Tool Registry (Complete 75 Tools)
Defines the strict whitelist of permissible tools, input schemas,
output schemas, permissions, and execution timeouts.
"""
from typing import Dict, Any

ALLOWLISTED_TOOLS: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------
    # 1. Email Protocol & PCAP Packet Forensics (15 Tools)
    # -------------------------------------------------------------
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
    "pcap.completeness": {
        "name": "pcap.completeness",
        "description": "Calculates capture completeness score, sequence gaps, retransmissions, and truncation.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"completeness_percentage": "number", "is_complete": "boolean", "assessment": "string"},
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
    "pcap.ip_fragments": {
        "name": "pcap.ip_fragments",
        "description": "Reassembles fragmented IP packets to detect evasion and fragmentation attacks.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"is_fragmented": "boolean", "fragment_count": "integer"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "pcap.integrity": {
        "name": "pcap.integrity",
        "description": "Validates PCAP SHA-256 and MD5 cryptographic integrity for custody ledger verification.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"valid": "boolean", "sha256": "string", "md5": "string"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "pcap.protocol_ratios": {
        "name": "pcap.protocol_ratios",
        "description": "Calculates ratio of plaintext vs encrypted protocol frames in the capture.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"counts": "object", "ratios": "object"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "pcap.port_anomalies": {
        "name": "pcap.port_anomalies",
        "description": "Flags email protocols running on non-standard network ports.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"anomalous_ports": "array"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "pcap.tcp_flags": {
        "name": "pcap.tcp_flags",
        "description": "Inspects TCP flags (SYN, FIN, RST, ACK) to detect post-STARTTLS connection resets.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"flag_distribution": "object", "has_rst_anomalies": "boolean"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "pcap.session_duration": {
        "name": "pcap.session_duration",
        "description": "Measures connection durations and idle timeouts across reconstructed email streams.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"durations": "array"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "pcap.packet_histogram": {
        "name": "pcap.packet_histogram",
        "description": "Computes packet length distribution to detect MTU anomalies and covert tunneling.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"size_buckets": "object"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "rules.evaluate": {
        "name": "rules.evaluate",
        "description": "Executes deterministic cryptographic rules across extracted forensic context.",
        "input_schema": {"forensic_context": "object"},
        "output_schema": {"triggered_rules": "array"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["forensic_context"]
    },

    # -------------------------------------------------------------
    # 2. Cryptographic & TLS Verification Tools (10 Tools)
    # -------------------------------------------------------------
    "tls.handshake": {
        "name": "tls.handshake",
        "description": "Parses TLS ClientHello/ServerHello, cipher suites, version negotiation, and key exchange.",
        "input_schema": {"file_path": "string", "stream_id": "string"},
        "output_schema": {"negotiated_version": "string", "selected_cipher": "object", "has_forward_secrecy": "boolean"},
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
    "ssl_scan": {
        "name": "ssl_scan",
        "description": "Audits SSL/TLS endpoint support, identity, and trust store policy compliance.",
        "input_schema": {"target": "string"},
        "output_schema": {"status": "string", "findings": "array"},
        "permission": "crypto_verify",
        "timeout": 15.0,
        "params": ["target"]
    },
    "tls_configuration_analysis": {
        "name": "tls_configuration_analysis",
        "description": "Identifies deprecated TLS 1.0/1.1 vs modern TLS 1.2/1.3 configurations.",
        "input_schema": {"tls_version": "string"},
        "output_schema": {"is_deprecated": "boolean", "recommendation": "string"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["tls_version"]
    },
    "cipher_suite_evaluator": {
        "name": "cipher_suite_evaluator",
        "description": "Scores cipher suite security, detecting RC4, 3DES, EXPORT, NULL, or CBC ciphers.",
        "input_schema": {"cipher_name": "string"},
        "output_schema": {"is_weak": "boolean", "has_forward_secrecy": "boolean", "security_score": "integer"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["cipher_name"]
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
    "certificate_revocation_checker": {
        "name": "certificate_revocation_checker",
        "description": "Performs OCSP and CRL validation status checks on extracted certificates.",
        "input_schema": {"cert_bytes_hex": "string"},
        "output_schema": {"is_revoked": "boolean", "ocsp_status": "string"},
        "permission": "crypto_verify",
        "timeout": 15.0,
        "params": ["cert_bytes_hex"]
    },
    "key_exchange_auditor": {
        "name": "key_exchange_auditor",
        "description": "Audits Diffie-Hellman (DH) and ECDHE key exchange bit lengths and forward secrecy.",
        "input_schema": {"tls_version": "string", "selected_cipher": "string"},
        "output_schema": {"status": "string", "forward_secrecy": "boolean", "bit_strength": "integer"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["tls_version"]
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

    # -------------------------------------------------------------
    # 3. Advanced Payload, YARA & Header Forensic Extensions (15 Tools)
    # -------------------------------------------------------------
    "yara.scan": {
        "name": "yara.scan",
        "description": "Scans payloads, text, or stream buffers against YARA regex rules for webshells, phishing, and macro scripts.",
        "input_schema": {"payload": "string"},
        "output_schema": {"has_matches": "boolean", "match_count": "integer", "matches": "array"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["payload"]
    },
    "pcap.entropy": {
        "name": "pcap.entropy",
        "description": "Calculates Shannon Entropy and byte frequency distribution across PCAP payload buffers.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"entropy": "number", "assessment": "string", "byte_counts": "object"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "dns.exfiltration": {
        "name": "dns.exfiltration",
        "description": "Inspects DNS queries for high subdomain entropy and covert data exfiltration patterns.",
        "input_schema": {"queries": "array"},
        "output_schema": {"is_dns_exfiltration_detected": "boolean", "suspicious_query_count": "integer"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["queries"]
    },
    "email.header_audit": {
        "name": "email.header_audit",
        "description": "Audits email headers for Return-Path mismatches, SPF/DKIM failures, and display name spoofing.",
        "input_schema": {"headers": "object"},
        "output_schema": {"is_suspicious": "boolean", "anomaly_count": "integer", "anomalies": "array"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["headers"]
    },
    "cyberchef.deobfuscate": {
        "name": "cyberchef.deobfuscate",
        "description": "Multi-stage deobfuscator applying Base64, Hex, URL, and Quoted-Printable recursive decoding.",
        "input_schema": {"payload": "string"},
        "output_schema": {"final_decoded_payload": "string", "pipeline_recipe": "array", "indicators": "object"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["payload"]
    },
    "email_security_analysis": {
        "name": "email_security_analysis",
        "description": "Audits domain MX records, SPF policy alignment, DMARC compliance, and MTA-STS policy.",
        "input_schema": {"domain": "string"},
        "output_schema": {"domain": "string", "mx": "array", "spf": "object", "dmarc": "object"},
        "permission": "external_network",
        "timeout": 15.0,
        "params": ["domain"]
    },
    "email.mime_structure": {
        "name": "email.mime_structure",
        "description": "Extracts MIME boundary layout and attachments with SHA-256 hashes.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"attachments": "array", "has_html": "boolean", "has_plain": "boolean"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "secret_pattern_analysis": {
        "name": "secret_pattern_analysis",
        "description": "Detects cleartext API keys, tokens, and passwords in payloads via Docker MCP.",
        "input_schema": {"content": "string"},
        "output_schema": {"matches": "array", "match_count": "integer"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["content"]
    },
    "jwt_security_test": {
        "name": "jwt_security_test",
        "description": "Decodes and tests JWT tokens for algorithm confusion ('none' alg) and unverified signatures.",
        "input_schema": {"token": "string"},
        "output_schema": {"header": "object", "payload": "object", "is_vulnerable": "boolean"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["token"]
    },
    "email.dkim_verify": {
        "name": "email.dkim_verify",
        "description": "Parses and verifies DKIM cryptographic signatures extracted from email headers.",
        "input_schema": {"headers": "object"},
        "output_schema": {"has_dkim": "boolean", "signatures": "array"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["headers"]
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
    "email.parse": {
        "name": "email.parse",
        "description": "Parses RFC-2822 / EML / MSG / MBOX artifact for headers, authentication records, and attachments.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"from_address": "string", "subject": "string", "authentication": "object"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "email.url_extractor": {
        "name": "email.url_extractor",
        "description": "Extracts hyperlinked URLs and domains from email messages for IOC analysis.",
        "input_schema": {"text": "string"},
        "output_schema": {"urls": "array", "count": "integer"},
        "permission": "read_artifact",
        "timeout": 10.0,
        "params": ["text"]
    },
    "base64.decode": {
        "name": "base64.decode",
        "description": "Decodes base64-encoded strings and payloads with safe ASCII extraction.",
        "input_schema": {"data": "string"},
        "output_schema": {"decoded": "string"},
        "permission": "read_artifact",
        "timeout": 10.0,
        "params": ["data"]
    },

    # -------------------------------------------------------------
    # 4. Machine Learning, Explainable AI & Ledger Integrity (10 Tools)
    # -------------------------------------------------------------
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
    "ml.extract_features": {
        "name": "ml.extract_features",
        "description": "Extracts normalized numeric and boolean feature vectors from forensic context.",
        "input_schema": {"forensic_context": "object"},
        "output_schema": {"features": "object", "vector": "array"},
        "permission": "ml_inference",
        "timeout": 10.0,
        "params": ["forensic_context"]
    },
    "finalize_finding": {
        "name": "finalize_finding",
        "description": "Registers a verified forensic finding supported by recorded evidence IDs.",
        "input_schema": {"title": "string", "description": "string", "severity": "string", "remediation": "string", "evidence_ids": "array"},
        "output_schema": {"status": "string", "finding_id": "string"},
        "permission": "ledger_write",
        "timeout": 10.0,
        "params": ["title", "description", "severity", "remediation", "evidence_ids"]
    },
    "ledger.verify_chain": {
        "name": "ledger.verify_chain",
        "description": "Validates the complete SHA-256 hash chain across all recorded evidence items.",
        "input_schema": {"investigation_id": "string"},
        "output_schema": {"is_valid": "boolean", "total_entries": "integer"},
        "permission": "read_artifact",
        "timeout": 10.0,
        "params": ["investigation_id"]
    },
    "report.generate_all": {
        "name": "report.generate_all",
        "description": "Generates immutable JSON, HTML, PDF, and SARIF forensic dossiers.",
        "input_schema": {"investigation_id": "string"},
        "output_schema": {"reports_generated": "array"},
        "permission": "generate_report",
        "timeout": 25.0,
        "params": ["investigation_id"]
    },
    "export.ids_rules": {
        "name": "export.ids_rules",
        "description": "Exports verified findings into Suricata IDS alert rules and Zeek scripts.",
        "input_schema": {"investigation_id": "string"},
        "output_schema": {"suricata_rules": "array", "zeek_scripts": "array"},
        "permission": "generate_report",
        "timeout": 15.0,
        "params": ["investigation_id"]
    },
    "posture.calculate": {
        "name": "posture.calculate",
        "description": "Computes overall security posture score (0-100) and risk level from verified evidence.",
        "input_schema": {"investigation_id": "string"},
        "output_schema": {"overall_posture_score": "number", "risk_level": "string"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["investigation_id"]
    },
    "risk.classify": {
        "name": "risk.classify",
        "description": "Categorizes investigation risk into CRITICAL, HIGH, MEDIUM, LOW, or SECURE.",
        "input_schema": {"score": "number"},
        "output_schema": {"risk_level": "string"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["score"]
    },
    "evidence.detect_contradictions": {
        "name": "evidence.detect_contradictions",
        "description": "Detects conflicting evidence claims across recorded forensic tool results.",
        "input_schema": {"investigation_id": "string"},
        "output_schema": {"has_contradictions": "boolean", "contradictions": "array"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["investigation_id"]
    },

    # -------------------------------------------------------------
    # 5. Docker MCP Scope-Safe Security Audit & Policy Engines (20 Tools)
    # -------------------------------------------------------------
    "dnssec_posture_analysis": {
        "name": "dnssec_posture_analysis",
        "description": "Inspects DNSKEY, DS, and RRSIG publication via Docker MCP.",
        "input_schema": {"domain": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["domain"]
    },
    "dangling_dns_analysis": {
        "name": "dangling_dns_analysis",
        "description": "Inspects CNAME targets for subdomain takeover indicators via Docker MCP.",
        "input_schema": {"domain": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["domain"]
    },
    "headers_analysis": {
        "name": "headers_analysis",
        "description": "Analyzes security and disclosure headers on web endpoints via Docker MCP.",
        "input_schema": {"target": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["target"]
    },
    "csp_analysis": {
        "name": "csp_analysis",
        "description": "Assesses Content Security Policy (CSP) directives for unsafe/missing controls via Docker MCP.",
        "input_schema": {"csp": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["csp"]
    },
    "cookie_security_analysis": {
        "name": "cookie_security_analysis",
        "description": "Inspects Set-Cookie attributes (SameSite, Secure, HttpOnly) via Docker MCP.",
        "input_schema": {"cookie_header": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["cookie_header"]
    },
    "cors_scan": {
        "name": "cors_scan",
        "description": "Analyzes cross-origin resource sharing policy headers via Docker MCP.",
        "input_schema": {"target": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["target"]
    },
    "cache_policy_analysis": {
        "name": "cache_policy_analysis",
        "description": "Assesses Cache-Control, Vary, and sensitive-path caching via Docker MCP.",
        "input_schema": {"headers": "object"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["headers"]
    },
    "http_method_analysis": {
        "name": "http_method_analysis",
        "description": "Assesses advertised HTTP methods (OPTIONS, TRACE) via Docker MCP.",
        "input_schema": {"target": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["target"]
    },
    "robots_txt_analysis": {
        "name": "robots_txt_analysis",
        "description": "Parses and summarizes robots.txt paths and sensitive exposures via Docker MCP.",
        "input_schema": {"content": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["content"]
    },
    "sitemap_analysis": {
        "name": "sitemap_analysis",
        "description": "Analyzes sitemap URLs for path disclosures via Docker MCP.",
        "input_schema": {"content": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["content"]
    },
    "security_txt_analysis": {
        "name": "security_txt_analysis",
        "description": "Validates RFC 9116 security.txt metadata and contact directives via Docker MCP.",
        "input_schema": {"content": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["content"]
    },
    "sri_analysis": {
        "name": "sri_analysis",
        "description": "Subresource Integrity coverage analysis for script and style tags via Docker MCP.",
        "input_schema": {"html": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["html"]
    },
    "openapi_security_analysis": {
        "name": "openapi_security_analysis",
        "description": "Audits OpenAPI / Swagger schemas for auth coverage and endpoint security via Docker MCP.",
        "input_schema": {"schema": "object"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["schema"]
    },
    "oauth_oidc_discovery": {
        "name": "oauth_oidc_discovery",
        "description": "Summarizes OIDC endpoints, grants, and PKCE support via Docker MCP.",
        "input_schema": {"config": "object"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["config"]
    },
    "graphql_endpoint_discovery": {
        "name": "graphql_endpoint_discovery",
        "description": "Probes read-only GraphQL schemas and introspection exposure via Docker MCP.",
        "input_schema": {"target": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["target"]
    },
    "technology_fingerprint": {
        "name": "technology_fingerprint",
        "description": "Fingerprints server software and web frameworks via Docker MCP.",
        "input_schema": {"headers": "object"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["headers"]
    },
    "cloud_asset_reference_analysis": {
        "name": "cloud_asset_reference_analysis",
        "description": "Extracts S3, GCS, and Azure Blob storage links from text via Docker MCP.",
        "input_schema": {"content": "string"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 15.0,
        "params": ["content"]
    },
    "cvss_v31_calculator": {
        "name": "cvss_v31_calculator",
        "description": "Calculates CVSS v3.1 base vector scores via Docker MCP.",
        "input_schema": {"vector": "string"},
        "output_schema": {"score": "number", "severity": "string"},
        "permission": "crypto_verify",
        "timeout": 10.0,
        "params": ["vector"]
    },
    "scope_check": {
        "name": "scope_check",
        "description": "Validates target authorization boundaries via Docker MCP.",
        "input_schema": {"target": "string"},
        "output_schema": {"in_scope": "boolean"},
        "permission": "external_intel",
        "timeout": 10.0,
        "params": ["target"]
    },
    "assessment_summary": {
        "name": "assessment_summary",
        "description": "Summarizes runtime metrics and finding severities via Docker MCP.",
        "input_schema": {"findings": "array"},
        "output_schema": {"summary": "object"},
        "permission": "generate_report",
        "timeout": 15.0,
        "params": ["findings"]
    },

    # -------------------------------------------------------------
    # 6. Host Utilities & System Dissectors (5 Native Tools)
    # -------------------------------------------------------------
    "host.tshark": {
        "name": "host.tshark",
        "description": "Executes Wireshark tshark dissection on PCAP capture.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"status": "string", "frames_summary": "array"},
        "permission": "read_artifact",
        "timeout": 20.0,
        "params": ["file_path"]
    },
    "host.capinfos": {
        "name": "host.capinfos",
        "description": "Runs capinfos on PCAP capture to retrieve capture statistics and duration.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"status": "string", "data": "object"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "host.zeek": {
        "name": "host.zeek",
        "description": "Runs Zeek network security monitor on capture to extract connection and protocol logs.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"status": "string", "logs": "object"},
        "permission": "read_artifact",
        "timeout": 25.0,
        "params": ["file_path"]
    },
    "host.tcpflow": {
        "name": "host.tcpflow",
        "description": "Runs tcpflow to reconstruct multi-stream TCP payload flows.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"status": "string", "stream_files": "array"},
        "permission": "read_artifact",
        "timeout": 20.0,
        "params": ["file_path"]
    },
    "host.openssl": {
        "name": "host.openssl",
        "description": "Runs OpenSSL x509 verification on extracted certificate data.",
        "input_schema": {"cert_pem": "string"},
        "output_schema": {"status": "string", "details": "object"},
        "permission": "crypto_verify",
        "timeout": 15.0,
        "params": ["cert_pem"]
    },

    # Backwards-compatible aliases and bridges
    "docker.mcp_call": {
        "name": "docker.mcp_call",
        "description": "Calls security tools provided by the Docker bugbounty-mcp image stdio bridge.",
        "input_schema": {"tool_name": "string", "arguments": "object"},
        "output_schema": {"result": "object"},
        "permission": "external_intel",
        "timeout": 20.0,
        "params": ["tool_name", "arguments"]
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
    "intel.ip": {
        "name": "intel.ip",
        "description": "Enriches endpoint IP reputation.",
        "input_schema": {"ip": "string"},
        "output_schema": {"reputation": "string"},
        "permission": "external_intel",
        "timeout": 10.0,
        "params": ["ip"]
    },
    "email.headers": {
        "name": "email.headers",
        "description": "Extracts header fields and Received hop chain from an EML artifact.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"headers": "object", "received_chain": "array"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
    },
    "email.authentication": {
        "name": "email.authentication",
        "description": "Extracts observed SPF, DKIM, and DMARC results from message headers.",
        "input_schema": {"file_path": "string"},
        "output_schema": {"spf_observed": "string", "dkim_observed": "string", "dmarc_observed": "string"},
        "permission": "read_artifact",
        "timeout": 15.0,
        "params": ["file_path"]
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
    }
}
