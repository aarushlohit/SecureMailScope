# SecureMailScope — Allowlisted Tool Registry

## 1. Security Principles
- **Strict Allowlisting**: Only tools declared in `ALLOWLISTED_TOOLS` in `securemailscope/tools/registry.py` may be invoked by the agent.
- **Sandboxed Parameter Validation**: Every parameter is checked against its expected type and schema. Shell strings, command substitution, and path traversals are rejected.
- **Execution Audit**: Every tool invocation records an immutable `ToolExecution` entry in the database containing duration, start/end timestamps, input arguments, and generated Evidence IDs.

## 2. Allowlisted Tools Specification

| Tool Name | Domain | Input Parameters | Output Schema |
|---|---|---|---|
| `pcap.inspect` | PCAP Framing | `file_path: string` | Hashes, packet count, duration, completeness |
| `pcap.sessions` | TCP Reassembly | `file_path: string` | Reconstructed streams, protocols |
| `pcap.tcp_stream`| Stream Flow | `file_path: string, stream_id: string` | Directional byte payloads, endpoints |
| `pcap.completeness`| Quality Score | `file_path: string` | Completeness percentage, sequence gaps |
| `smtp.analyze` | SMTP FSM | `file_path: string, stream_id: string` | STARTTLS advertisement, plaintext continuation |
| `imap.analyze` | IMAP FSM | `file_path: string, stream_id: string` | Capabilities, STARTTLS, cleartext auth |
| `pop3.analyze` | POP3 FSM | `file_path: string, stream_id: string` | STLS capabilities, plaintext credentials |
| `starttls.analyze`| Cross-Protocol | `file_path: string, stream_id: string` | STARTTLS negotiation status |
| `tls.handshake` | TLS Handshake | `file_path: string, stream_id: string` | Version, cipher suite, forward secrecy |
| `tls.features` | TLS Extensions | `file_path: string, stream_id: string` | SNI, ALPN, supported groups |
| `tls.certificate` | X.509 Extraction| `file_path: string, stream_id: string` | Subject, issuer, validity, or NOT_OBSERVABLE |
| `certificate.validate`| Crypto Verify | `cert_bytes_hex: string, hostname: string` | Trust store status, SAN matching |
| `ml.predict` | XGBoost ML | `forensic_context: object` | Predicted class, risk probability |
| `ml.explain` | SHAP TreeExplainer| `forensic_context: object` | Top contributing features and SHAP values |
| `email.parse` | EML Artifact | `file_path: string` | Headers, authentication, MIME, attachments |
| `email.headers` | EML Headers | `file_path: string` | Received hop chain, From, To, Subject |
| `email.authentication`| EML SPF/DKIM/DMARC | `file_path: string` | Observed authentication results from headers |
| `email.mime_structure`| EML Attachments | `file_path: string` | Attachment filenames, types, SHA-256 hashes |
| `dns.mx` | External DNS | `domain: string` | MX records, mail exchangers |
| `dns.spf` | External DNS | `domain: string` | SPF TXT record evaluation |
| `dns.dmarc` | External DNS | `domain: string` | DMARC policy record evaluation |
| `dns.mta_sts` | External DNS | `domain: string` | MTA-STS policy check |
| `dns.tlsa` | External DNS | `domain: string, port: integer` | DANE TLSA record check |
| `intel.tavily_search`| External Intel | `query: string` | Real-time web intelligence results |
| `report.generate_json`| Dossier Export | `investigation_id: string` | Machine-readable JSON dossier |
| `report.generate_html`| Dossier Export | `investigation_id: string` | Standalone HTML report |
| `report.generate_pdf` | Dossier Export | `investigation_id: string` | Audit-grade PDF report |
