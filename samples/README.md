# SecureMailScope Sample Captures Dataset

This directory contains forensic PCAP/PCAPNG captures used for automated testing, demonstration, and forensic engine validation in **SecureMailScope** (*Agentic Cryptographic Forensics for Secure Email Communications*).

Captures are categorized into two tiers:
1. **Authentic Full-Stack Captures**: Real-world network traffic captures sourced from the Wireshark Foundation sample capture repository.
2. **Synthetic Scenario Fixtures**: Deterministic micro-captures generated using Scapy and Cryptography libraries to simulate explicit vulnerability conditions and edge-cases (downgrade attacks, certificate expiration, truncation).

---

## 1. Authentic Real-World Captures (Wireshark Foundation)

### `wireshark_real_smtp.pcap`
- **Type**: Authentic (Real-world capture)
- **Origin / License**: Wireshark Foundation Sample Captures (`smtp.pcap`), Public Domain / GNU GPL.
- **Format**: PCAP (Ethernet encapsulation, microsecond precision)
- **File Size**: 27,850 bytes
- **Packet Count**: 60 packets
- **Capture Duration**: 9.198 seconds
- **SHA-256**: `17ad230db1b6fd5dd18eb311092df1cf6eb162054bdb47697b89bef5a86a47ab`
- **Protocols Observed**: TCP, SMTP (Plaintext port 25)
- **Observed Behavior**: Complete authentic SMTP transaction containing `EHLO`, `MAIL FROM`, `RCPT TO`, `DATA`, message body delivery, and `QUIT`. Demonstrates passive RFC 5321 analysis and extraction of envelope headers.

### `wireshark_real_imap.pcap`
- **Type**: Authentic (Real-world capture)
- **Origin / License**: Wireshark Foundation Sample Captures (`imap.pcap`), Public Domain / GNU GPL.
- **Format**: PCAP (Ethernet encapsulation, microsecond precision)
- **File Size**: 31,417 bytes
- **Packet Count**: 124 packets
- **Capture Duration**: 25.781 seconds
- **SHA-256**: `fa9a9bcca7b7f2943d740d46b075565b0dbbcc0f60ab321bf577a7be9724b5a8`
- **Protocols Observed**: TCP, IMAP (Port 143)
- **Observed Behavior**: Interactive client IMAP session with authentication, mailbox listing (`LIST`), folder selection (`SELECT "INBOX"`), and message fetch sequence (`FETCH`). Demonstrates mailbox state tracking.

### `wireshark_real_smtp_ssl.pcapng`
- **Type**: Authentic (Real-world capture)
- **Origin / License**: Wireshark Foundation Sample Captures (`smtp-ssl.pcapng`), Public Domain / GNU GPL.
- **Format**: PCAPNG (Linux 3.18, nanosecond precision, Dumpcap 1.99.1)
- **File Size**: 8,968 bytes
- **Packet Count**: 38 packets
- **Capture Duration**: 1,522,669,095.87 seconds
- **SHA-256**: `ca2f8af9de247be43b3a0b8cca6795bc7a2a8076719c572beed6662e1ea46eb4`
- **Protocols Observed**: TCP, SMTP, TLSv1.2 (Port 25, STARTTLS transition)
- **Observed Behavior**: SMTP conversation on TCP port 25 that executes `EHLO`, advertises `STARTTLS`, issues `STARTTLS` command, receives `220 2.0.0 Ready to start TLS`, and negotiates a genuine TLS 1.2 handshake.

### `wireshark_real_pop_ssl.pcapng`
- **Type**: Authentic (Real-world capture)
- **Origin / License**: Wireshark Foundation Sample Captures (`pop-ssl.pcapng`), Public Domain / GNU GPL.
- **Format**: PCAPNG (Linux 3.18, nanosecond precision, Dumpcap 1.99.1)
- **File Size**: 9,400 bytes
- **Packet Count**: 38 packets
- **Capture Duration**: 1,537,912,832.75 seconds
- **SHA-256**: `a9bf0b6c9125c181969c1e68718f1ad68bf7f091d5f115fb4089c983273e0e5d`
- **Protocols Observed**: TCP, POP3, TLSv1.2 (Port 110, STLS transition)
- **Observed Behavior**: Authentic POP3 transaction on port 110 executing `CAPA`, issuing `STLS`, receiving `+OK Begin TLS negotiation`, and completing a secure TLS 1.2 handshake.

### `wireshark_real_imap_ssl.pcapng`
- **Type**: Authentic (Real-world capture)
- **Origin / License**: Wireshark Foundation Sample Captures (`imap-ssl.pcapng`), Public Domain / GNU GPL.
- **Format**: PCAPNG (Linux 3.18, nanosecond precision, Dumpcap 1.99.1)
- **File Size**: 10,152 bytes
- **Packet Count**: 41 packets
- **Capture Duration**: 1,538,646,470.98 seconds
- **SHA-256**: `c988a888d2a6f93d70d383eef4b8cd0c27e440266d0f61980f33b94da9a3ad61`
- **Protocols Observed**: TCP, IMAP, TLSv1.2 (Port 143, STARTTLS transition)
- **Observed Behavior**: Authentic IMAP conversation on port 143 executing `CAPABILITY`, issuing `. STARTTLS`, receiving `. OK Begin TLS negotiation now`, and establishing a TLS 1.2 session.

---

## 2. Synthetic Scenario Fixtures (Project-Authored)

All synthetic fixtures are generated deterministically and licensed under the MIT License.

### `mail_attack_starttls_strip.pcap`
- **Type**: Synthetic Scenario Fixture
- **Origin / License**: SecureMailScope Project / MIT
- **Format**: PCAP
- **File Size**: 1,469 bytes
- **Packet Count**: 15 packets
- **SHA-256**: `c36d812cd9037d9a5a4e443d40c8ea29f4742274414afaef07f5b735a3375731`
- **Protocols Observed**: TCP, SMTP (Plaintext downgrade)
- **Observed Behavior**: Simulates an active STARTTLS stripping / downgrade attack. Server advertises STARTTLS, client issues STARTTLS, server acknowledges, but unencrypted `MAIL FROM` and `DATA` commands follow without any TLS ClientHello. Triggers `RULE-STARTTLS-001` (CRITICAL).

### `mail_imap_cert_expired.pcap`
- **Type**: Synthetic Scenario Fixture
- **Origin / License**: SecureMailScope Project / MIT
- **Format**: PCAP
- **File Size**: 1,647 bytes
- **Packet Count**: 8 packets
- **SHA-256**: `78c16f91f95be1b3c0e2dca7d8c77cb79d43c23da13aa1370914aae8605ec61b`
- **Protocols Observed**: TCP, IMAP, TLS 1.2
- **Observed Behavior**: IMAP TLS session presenting an expired and self-signed X.509 server certificate. Demonstrates observable certificate parsing and trust store validation failure. Triggers `RULE-CERT-001` and `RULE-CERT-002` (HIGH).

### `mail_partial_capture_inconclusive.pcap`
- **Type**: Synthetic Scenario Fixture
- **Origin / License**: SecureMailScope Project / MIT
- **Format**: PCAP
- **File Size**: 558 bytes
- **Packet Count**: 7 packets
- **SHA-256**: `bdb894da94ce5e1e38c57760812e553aea0478aa2ac657d7cd0e80a61cabada9`
- **Protocols Observed**: TCP, Truncated SMTP
- **Observed Behavior**: Demonstrates capture completeness assessment (<60% sequence continuity). Resolves inconclusive status rather than hallucinating an attack when missing packets explain missing handshakes.

### `mail_pop3_plaintext_auth.pcap`
- **Type**: Synthetic Scenario Fixture
- **Origin / License**: SecureMailScope Project / MIT
- **Format**: PCAP
- **File Size**: 1,469 bytes
- **Packet Count**: 15 packets
- **SHA-256**: `5c9b695c07d1adca0615be6d2731af02d953dab6984f1a12a99f8bd7f23af703`
- **Protocols Observed**: TCP, POP3
- **Observed Behavior**: POP3 session transmitting cleartext authentication commands (`USER`, `PASS`) over unencrypted port 110 without attempting STLS. Triggers `RULE-PLAINTEXT-002` (HIGH).

### `mail_secure_tls13.pcap`
- **Type**: Synthetic Scenario Fixture
- **Origin / License**: SecureMailScope Project / MIT
- **Format**: PCAP
- **File Size**: 1,156 bytes
- **Packet Count**: 11 packets
- **SHA-256**: `e60f1545c9d0f85935f17d4c1e15edbd8353ef1db3ab1c1184a21b82356da9be`
- **Protocols Observed**: TCP, TLS 1.3 (Port 465)
- **Observed Behavior**: High-security TLS 1.3 encrypted email transport with AES-256-GCM and forward secrecy. Demonstrates honest passive limitation noting that TLS 1.3 certificates are encrypted post-ServerHello.

### `mail_weak_crypto_tls10_rc4.pcap`
- **Type**: Synthetic Scenario Fixture
- **Origin / License**: SecureMailScope Project / MIT
- **Format**: PCAP
- **File Size**: 1,540 bytes
- **Packet Count**: 10 packets
- **SHA-256**: `a10fe2463c275cd984fcad156af7f82b4a5f22e5352fcd649ac488a38d1d5e82`
- **Protocols Observed**: TCP, TLS 1.0 (Port 465)
- **Observed Behavior**: Legacy TLS 1.0 session negotiating broken RC4-SHA cipher suite without forward secrecy. Triggers `RULE-TLS-001` and `RULE-CIPHER-001` (HIGH).
