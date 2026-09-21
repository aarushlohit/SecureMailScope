# SecureMailScope
## Agentic Cryptographic Forensics for Secure Email Communications

**SIH 2026 Problem Statement:** SIH26159  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  

---

## 1. Executive Summary

**SecureMailScope** is an **evidence-first, AI-assisted cryptographic forensic platform** designed to assess the security posture of SMTP, IMAP, and POP3 communications from passive network captures (PCAP/PCAPNG) and message archives (EML).

The platform reconstructs email communication sessions from raw captures and deterministically analyzes:
- **Protocol State Machines**: SMTP, IMAP, and POP3 state transitions, command flows, and cleartext credential exposure.
- **STARTTLS Negotiation**: 10-state machine tracing `CONNECTED` &rarr; `GREETING` &rarr; `CAPABILITY/EHLO` &rarr; `STARTTLS_ADVERTISED` &rarr; `STARTTLS_REQUESTED` &rarr; `STARTTLS_ACCEPTED` &rarr; `TLS_NEGOTIATION` &rarr; `ENCRYPTED` &rarr; `PLAINTEXT_FALLBACK` &rarr; `FAILED`.
- **Capture Completeness**: TCP sequence gap analysis, retransmission counts, truncation penalties, and packet-loss confidence scoring.
- **TLS Handshake Forensics**: Version negotiation (TLS 1.0 to 1.3), cipher suite auditing, Perfect Forward Secrecy (PFS), ALPN, and SNI.
- **Observable X.509 Certificates**: Public key strength, validity periods, Subject Alternative Name (SAN) validation, self-signed detection, and chain analysis.
- **Honest TLS 1.3 Observability**: Explicit `NOT_OBSERVABLE` status for post-ServerHello encrypted certificate handshakes (never manufactures synthetic certs).
- **Machine Learning Layer**: Gradient-boosted tree classifier (XGBoost) evaluating 15 cryptographic features with explainable SHAP attributions.
- **Stateful Investigation Agent**: Explicit state machine (`OBSERVE` &rarr; `HYPOTHESIZE` &rarr; `PLAN` &rarr; `SELECT TOOL` &rarr; `EXECUTE` &rarr; `STORE EVIDENCE` &rarr; `CORRELATE` &rarr; `RE-EVALUATE` &rarr; `VERIFY` &rarr; `VERDICT`).
- **No Evidence &rarr; No Finding Gatekeeper**: Findings strictly require existing evidence IDs with verified provenance chains.

---

## 2. Architecture & Dependency Inversion

SecureMailScope enforces a strict one-way dependency chain:
```
PCAP / PCAPNG / EML Capture
       ↓
Deterministic Forensic Engines (TShark, Capinfos, OpenSSL, Scapy, RFC-822 Parsers)
       ↓
Evidence Ledger & Database (SQLite / SQLAlchemy / Alembic)
       ↓
Machine Learning (XGBoost) & Deterministic Crypto Rules
       ↓
Stateful Investigation Agent
       ↓
LLM Router (Priority 1: NVIDIA NIM Llama 3.2 | Priority 2: Gemini 2.5 Flash Lite | Priority 3: Deterministic Fallback)
```

> **CRITICAL GUARANTEE:** The LLM reasons *over* established facts. It never creates, hallucinates, or modifies evidence. When external LLM API keys are missing or offline, the entire forensic engine, finding validator, and reporting operate with zero loss of forensic accuracy.

---

## 3. Tech Stack & External Credentials

### External Credentials (Exactly Three):
1. **NVIDIA NIM** (`NVIDIA_API_KEY`): Primary LLM (`meta/llama-3.2-11b-vision-instruct`) via OpenAI-compatible endpoints with structured tool-calling.
2. **Google Gemini** (`GEMINI_API_KEY`): Fallback LLM (`gemini-2.5-flash-lite`) via Google GenAI REST API with native function declarations.
3. **Tavily** (`TAVILY_API_KEY`): External OSINT threat search (`intel.tavily_search`) strictly tagged as `EXTERNAL_INTELLIGENCE`.

### Backend & Data Science:
- **FastAPI & Uvicorn**: Async REST API and Server-Sent Events (SSE) / WebSocket streaming.
- **SQLAlchemy 2.0 & SQLite / Alembic**: Database models, migrations, and database-level immutability triggers.
- **Scapy & System Binaries**: `tshark`, `capinfos`, `openssl` for deep packet inspection.
- **XGBoost & Scikit-learn**: Tabular cryptographic risk classification.
- **SHAP**: TreeExplainer for feature importance attributions.
- **ReportLab & Jinja2**: Multi-format audit reporting (JSON, HTML, PDF).

---

## 4. Evidence-Ledger Integrity Model

The Evidence Ledger serves as the immutable ground-truth store:
1. **Application-Level Immutability**: Any attempt to overwrite or modify an existing `evidence_id` raises `EvidenceMutationError` and logs a `MUTATION_ATTEMPT_BLOCKED` audit event.
2. **Database-Level Immutability Triggers**: SQLite engine triggers (`prevent_evidence_update` and `prevent_evidence_delete`) abort raw SQL `UPDATE` and `DELETE` queries with `IMMUTABLE_VIOLATION`.
3. **Cryptographic SHA-256 Hash Chaining**: Each record stores its canonical JSON representation, the `previous_entry_hash` (initialized with 64 zero characters at `GENESIS_HASH`), and computes an `entry_hash = SHA256(canonical_json + previous_entry_hash)`.
4. **Referential Finding Validation**: Findings require valid, existing evidence IDs within the same investigation. Cross-investigation and cross-user citations are strictly rejected.
5. **Auditing CLI**: `python -m securemailscope.cli verify-ledger` validates the complete sequential hash chain and citation graph.

---

## 5. Security & Authorization Architecture

- **Password Hashing**: PBKDF2-HMAC-SHA256 with 600,000 iterations and 16-byte cryptographic salts.
- **Database-Backed Sessions**: Tokens are signed HMAC-SHA256 JWTs; their SHA-256 hash is tracked in the `auth_sessions` table.
- **Persistent Revocation**: Logout sets `revoked_at` in the database. Revoked sessions remain rejected across server restarts and in-memory cache clears.
- **IDOR Protection**: All investigation, evidence, timeline, finding, and report endpoints enforce user ownership via `require_owned_investigation_model`.
- **WebSocket Security**: `/ws/{investigation_id}` authenticates bearer tokens against the database and validates ownership before accepting the connection.
- **CORS Hardening**: Explicitly restricted to trusted local origin domains (`localhost:8000`, `127.0.0.1:8000`, `localhost:3000`, `127.0.0.1:3000`).

---

## 6. Supported Input Formats

- **PCAP**: Standard libpcap captures (Little-Endian / Big-Endian).
- **PCAP-NG**: Next Generation Section Header Block format.
- **CAP**: Legacy capture formats.
- **EML**: RFC-822 / RFC-2822 email message archives with MIME multipart and header inspection.

---

## 7. Installation & Quick Start

### 1. Environment Setup
```bash
# Clone and enter directory
cd /home/aarush/Myoffice/hackathons/SIH

# Activate existing or create fresh virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install frozen dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
```

### 2. Database Initialization
```bash
python -c "from securemailscope.db.session import init_db; init_db()"
```

### 3. Launch Web Console
```bash
python -m securemailscope.cli serve --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

---

## 8. Verification & Audit Commands

### 1. Full Pytest Suite (81 Tests)
```bash
pytest tests/ -v
```

### 2. Evidence Ledger Integrity Check
```bash
python -m securemailscope.cli verify-ledger
```

### 3. Live External AI Provider Validation
```bash
# NVIDIA NIM (Llama 3.2 11B Vision Instruct)
python scripts/live_nvidia_validation.py

# Google Gemini (Gemini 2.5 Flash Lite)
python scripts/live_gemini_validation.py
```

### 4. Standalone Report Generation
```bash
python -m securemailscope.cli report INV-REAL-SMTP-01 --format json
python -m securemailscope.cli report INV-REAL-SMTP-01 --format html
python -m securemailscope.cli report INV-REAL-SMTP-01 --format pdf
```

---

## 9. Demo Presentation Flow (Judges' Walkthrough)

1. **Authentication**: Register a new analyst account at `/signup` or log in at `/login`.
2. **PCAP Ingestion**: Upload `samples/wireshark_real_smtp.pcap` or select from pre-packaged demonstration captures.
3. **Session Reconstruction**: Inspect reassembled TCP streams, directional payload flows, and protocol handshakes.
4. **Evidence & Posture Score**: Review the explainable security posture score (0-100), completeness penalties, and findings.
5. **Agentic Tool Calling**: Observe real-time agent reasoning steps streaming over SSE/WebSocket.
6. **Multi-Format Export**: Download publication-ready PDF, standalone HTML, or structured JSON forensic dossiers.
7. **Ledger Audit**: Run `python -m securemailscope.cli verify-ledger` in the terminal to demonstrate cryptographic tamper detection live.

---

## 10. Verification Status & Limitations

### Status
> **Verified within the tested scope.**  
> All 81 unit/integration tests pass. Cryptographic hash chain of 1,153 entries validated. Live NVIDIA NIM and Google Gemini function-calling round trips confirmed against real network captures.

### Known Limitations
1. **Public Diagnostic Endpoints**: `/api/intel/query` and `/api/ml/benchmark` are intentionally public for demonstration without bearer tokens.
2. **Cookie `secure` Flag**: Set to `secure=False` by default to enable local plaintext HTTP development (`http://localhost:8000`). Production deployments behind HTTPS reverse proxies must configure `secure=True`.
3. **Upstream AI Provider Quotas**: In the event of upstream rate limiting on third-party AI APIs, the system automatically falls back to local deterministic rule-based forensics with zero loss of cryptographic accuracy.

---

## 11. Future Improvements

- Automated DANE / TLSA validator engine via direct DNSSEC resolver.
- Hardware-accelerated PCAP parsing for multi-gigabyte continuous capture rings.
- Dynamic TLS session key decryption via provided SSLKEYLOGFILE artifacts.
