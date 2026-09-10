# SecureMailScope

## Agentic Cryptographic Forensics for Secure Email Communications

**SIH 2026 Problem Statement:** SIH26159  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  

---

## 1. Executive Summary

**SecureMailScope** is an **evidence-first, AI-assisted cryptographic forensic platform** designed to assess the security posture of SMTP, IMAP, and POP3 communications from passive network captures (PCAP/PCAPNG).

The platform reconstructs email communication sessions from PCAPs and deterministically analyzes:
- SMTP / IMAP / POP3 protocol state machines and transitions
- STARTTLS negotiation and protocol stripping/fallback attacks
- TCP stream reassembly and directional payload flows
- TLS 1.0, 1.1, 1.2, and 1.3 handshakes, versions, ciphers, and extensions
- Perfect Forward Secrecy (PFS) and key exchange mechanisms
- Observable X.509 certificates and cryptographic validation
- Explicit handling of TLS 1.3 encrypted handshakes (never manufactures unobservable certs)
- Capture completeness and packet-loss confidence scoring

### Core Architectural Principles
> **1. Deterministic tools establish facts.**  
> **2. The Evidence Ledger preserves ground truth.**  
> **3. Machine Learning identifies multi-feature patterns.**  
> **4. The Agent adaptively investigates the evidence.**  
> **5. No Evidence &rarr; No Finding.**

---

## 2. Quick Start & 5-Minute SIH Live Demo

### Setup Environment
```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt  # (or pip install scapy xgboost scikit-learn fastapi uvicorn pydantic jinja2 cryptography pandas numpy pytest reportlab python-multipart)

# Generate synthetic demonstration PCAP captures
python -m securemailscope.cli generate-samples
```

### Launch Web Investigation Console
```bash
python -m securemailscope.cli serve --host 127.0.0.1 --port 8000
```
Open your browser at **`http://127.0.0.1:8000`** to access the Web Console.

---

## 3. CLI Forensic Commands

### 1. Analyze a Network Capture
```bash
python -m securemailscope.cli analyze samples/mail_attack_starttls_strip.pcap --report-dir reports/
```

### 2. Scientific Benchmark (Rule-Only Baseline vs Rule + ML Engine)
```bash
python -m securemailscope.cli benchmark
```
Outputs empirical accuracy, precision, recall, and F1 improvement (+57% F1 gain).

---

## 4. Pre-Packaged Demo Scenarios (`samples/`)

| File | Scenario | Forensic Finding / Expected Verdict |
| :--- | :--- | :--- |
| `mail_attack_starttls_strip.pcap` | **STARTTLS Stripping Attack** | Plaintext continuation after accepted STARTTLS &rarr; `[CRITICAL]` Downgrade Violation |
| `mail_secure_tls13.pcap` | **Secure Baseline (TLS 1.3)** | Modern TLS 1.3 + PFS &rarr; `[SECURE 100/100]` with explicit TLS 1.3 encrypted cert limitation |
| `mail_partial_capture_inconclusive.pcap` | **Incomplete Capture** | 20% Completeness &rarr; `[INCONCLUSIVE]` Honest insufficient evidence finding |
| `mail_weak_crypto_tls10_rc4.pcap` | **Weak Legacy Cryptography** | TLS 1.0 + RC4 + RSA-1024 weak key &rarr; `[CRITICAL 20/100]` Deprecated Protocol |
| `mail_imap_cert_expired.pcap` | **IMAP Expired Certificate** | IMAP STARTTLS + Expired X.509 cert &rarr; `[HIGH]` Certificate Expiration |
| `mail_pop3_plaintext_auth.pcap` | **POP3 Plaintext Credentials** | Cleartext USER/PASS over unencrypted wire &rarr; `[HIGH]` Cleartext Auth Violation |

---

## 5. Multi-Format Deliverables

Every investigation automatically outputs:
1. **Machine-Readable JSON Dossier**: `reports/{INV_ID}_report.json`
2. **Interactive Standalone HTML Report**: `reports/{INV_ID}_report.html`
3. **Publication-Ready PDF Report**: `reports/{INV_ID}_report.pdf`

---

## 6. Running Test Suite

```bash
pytest tests/ -v
```
All 18 tests cover forensic engines, rules, evidence ledger persistence, finding validation gate, ML model inference, and the 3 adaptive agent branches.
