"""
SecureMailScope - Tool Registry
"""
from typing import Dict, Any, List

ALLOWLISTED_TOOLS = {
    "pcap.inspect": {
        "description": "Validates PCAP framing, extracts packet count, timestamps, SHA-256 and MD5 hashes.",
        "params": ["file_path"]
    },
    "pcap.completeness": {
        "description": "Calculates TCP sequence continuity, retransmissions, truncation and overall capture completeness.",
        "params": ["file_path"]
    },
    "pcap.sessions": {
        "description": "Discovers protocol sessions (SMTP, IMAP, POP3, TLS) across reconstructed TCP streams.",
        "params": ["file_path"]
    },
    "pcap.tcp_stream": {
        "description": "Reconstructs directional conversation payloads and sequence timeline for a specific TCP stream.",
        "params": ["file_path", "stream_id"]
    },
    "smtp.analyze": {
        "description": "Evaluates SMTP state machine, STARTTLS transitions, cleartext commands, and stripping anomalies.",
        "params": ["file_path", "stream_id"]
    },
    "imap.analyze": {
        "description": "Evaluates IMAP state machine, STARTTLS capabilities, OK responses, and cleartext auth.",
        "params": ["file_path", "stream_id"]
    },
    "pop3.analyze": {
        "description": "Evaluates POP3 state machine, STLS capabilities, +OK transitions, and cleartext credentials.",
        "params": ["file_path", "stream_id"]
    },
    "tls.handshake": {
        "description": "Parses TLS ClientHello/ServerHello, cipher suites, version negotiation, and extension parameters.",
        "params": ["file_path", "stream_id"]
    },
    "tls.certificate": {
        "description": "Extracts observable X.509 certificates from unencrypted TLS handshakes (TLS <= 1.2).",
        "params": ["file_path", "stream_id"]
    },
    "certificate.validate": {
        "description": "Performs cryptographic verification of X.509 certificate bytes against trust store and rules.",
        "params": ["cert_bytes_hex", "hostname"]
    },
    "rules.evaluate": {
        "description": "Executes deterministic cryptographic rules across extracted protocol and TLS forensic context.",
        "params": ["forensic_context"]
    },
    "intel.ip": {
        "description": "Queries controlled threat intelligence and reputation for an IP address.",
        "params": ["ip"]
    },
    "intel.domain": {
        "description": "Queries domain security reputation, MTA-STS, and DANE DNSSEC posture.",
        "params": ["domain"]
    },
    "intel.certificate": {
        "description": "Enriches certificate fingerprint via Certificate Transparency logs.",
        "params": ["fingerprint"]
    }
}
