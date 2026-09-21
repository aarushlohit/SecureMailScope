# SecureMailScope — Forensic Dataset & Capture Profiles

## 1. Capture Dataset Inventory
SecureMailScope bundles authentic, RFC-compliant network captures covering distinct cryptographic and protocol scenarios in `samples/`:

| File Name | Protocol | Focus Scenario | Authentic Findings |
|---|---|---|---|
| `wireshark_real_smtp.pcap` | SMTP | Real-world SMTP traffic | Real packet framing, TCP gap tracking, STARTTLS analysis |
| `starttls_stripping_attack.pcap` | SMTP | MitM downgrade attack | Advertised STARTTLS bypassed, cleartext authentication |
| `deprecated_tls10_ciphers.pcap` | SMTP/TLS | Legacy protocol risk | TLS 1.0 handshake, 3DES/RC4 cipher suite |
| `expired_certificate.pcap` | SMTP/TLS | Certificate failure | X.509 validity expired, self-signed issuer |
| `pop3_plaintext_auth.pcap` | POP3 | Cleartext credential exposure | Port 110 USER/PASS commands sent in the clear |
| `imap_cleartext_login.pcap` | IMAP | Unencrypted mailbox access | Port 143 LOGIN command without STARTTLS |

## 2. Dataset Synthesis & Integrity
- Synthesized captures are generated with authentic byte-level protocol framing via Scapy in `DatasetGenerator`.
- Synthetic captures are never hardcoded in the frontend; each file is analyzed dynamically by the full forensic pipeline.
- Regeneratable at any time via:
  ```bash
  python -m securemailscope.cli generate-samples
  ```
