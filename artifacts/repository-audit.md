# SecureMailScope — Repository Audit Report
**Date:** 2026-09-11  
**Project:** SecureMailScope — Agentic Cryptographic Forensics for Secure Email Communications  
**Platform:** Linux x86_64 | Python 3.14.7 | FastAPI | SQLite | Scapy 2.7.0  

---

## 1. Executive Audit Overview
This audit document details the forensic, cryptographic, architectural, and security posture of the SecureMailScope codebase at `/home/aarush/Myoffice/hackathons/SIH`. Every subsystem was evaluated against production-grade non-negotiable requirements: zero synthetic shortcuts, zero hardcoded findings, genuine external LLM tool-calling orchestration, referential database integrity, and tamper-evident evidence ledgering.

---

## 2. Subsystem Audit Findings

### A. Core Architecture & Backend Services
- **FastAPI Application (`securemailscope/api/`)**:
  - Modular routers for `/api/auth`, `/api/investigations`, `/api/ml`, `/api/reports`, `/api/system`, and `/api/events` (SSE).
  - Sanitized error handling: Custom exception handlers prevent stack trace leakage and internal SQL structure disclosure (`FastAPIHTTPException` and `RequestValidationError`).
  - Strict input validation: Magic bytes, file size limits (50MB), filename sanitization, and path resolution.

### B. Forensics & Packet Dissection Engine (`securemailscope/forensics/`)
- **Passive PCAP Parsing (`capture.py`, `tcp_stream.py`)**:
  - Scapy-based L2-L7 dissection with TShark (`/usr/bin/tshark`) and Capinfos (`/usr/bin/capinfos`) verification.
  - Reassembles full TCP streams, identifies directional client/server segments, and extracts application payloads.
  - RFC 5321 (SMTP), RFC 3501 (IMAP), and RFC 1939 (POP3) finite state machines track command/response handshakes, STARTTLS/STLS transitions, and authentication commands (`AUTH PLAIN`, `AUTH LOGIN`).
- **Cryptographic TLS & Certificate Engine (`tls_engine.py`, `certificate.py`)**:
  - Extracts TLS Record Layer metadata: ClientHello, ServerHello, ProtocolVersion, and CipherSuite.
  - Transparently identifies TLS 1.0, 1.1, 1.2, and 1.3.
  - **Honest Cryptographic Limitation**: Correctly identifies that TLS 1.3 certificates are encrypted post-ServerHello (`Certificate` handshake message encrypted under handshake keys); marks certificate as `NOT_OBSERVABLE` without fabricated claims.
  - OpenSSL/Cryptography library extracts X.509 certificates (DER/PEM), validates expiration dates (`not_valid_after`), subject/issuer DNs, public key algorithm, and self-signed status.
- **RFC-2822 EML Forensics (`email_parser.py`)**:
  - Implemented real email parsing using `mailparser` with stdlib `email` fallback.
  - Extracts From, To, CC, Date, Subject, Message-ID, Received hops, MIME boundaries, and attachments with computed SHA-256 hashes.
  - Captures observed SPF, DKIM, and DMARC headers with explicit disclosures that they are unverified claims observed from the header.

### C. Evidence Ledger & Findings Validator (`securemailscope/evidence/`)
- **Immutable Evidence Ledger (`ledger.py`)**:
  - Append-only ground truth store persisted in SQLite (`EvidenceModel`) and synchronized with `data/evidence_ledger.json`.
  - Cryptographic hash chaining: Each record binds previous hash, evidence ID, investigation ID, claim, and source tool.
- **Finding Validator (`validator.py`)**:
  - Enforces the core mandate: **"No Evidence -> No Finding"**.
  - Rejects findings with empty evidence citations (`EvidenceValidationError`).
  - Rejects findings citing nonexistent evidence IDs.
  - Rejects findings citing evidence from different investigations (cross-investigation isolation).
  - Rejects findings citing evidence lacking provenance chains.

### D. Machine Learning & Explainability Engine (`securemailscope/ml/`)
- **XGBoost Classifier (`model.py`)**:
  - 15-dimensional forensic feature vector extracted directly from dissected packet and session evidence.
  - Multi-class probability estimation (`multi:softprob`) across risk classes.
- **SHAP Explainability (`shap.TreeExplainer`)**:
  - Integrated real SHAP engine (`shap.TreeExplainer`) on fitted XGBoost model.
  - Returns top 5 feature contributors with feature name, value, Shapley impact magnitude, and directionality (`risk` vs `safe`).
  - Replaced static placeholder structures with dynamic SHAP evaluation.

### E. LLM Routing, Health Checks & Tool Calling (`backend/llm/`)
- **Dual-Provider Routing (`router.py`)**:
  - Primary: NVIDIA NIM (`meta/llama-3.2-11b-vision-instruct` via OpenAI-compatible endpoint).
  - Secondary Fallback: Google Gemini (`gemini-3.6-flash` via Google Generative Language API).
  - Fail-Safe: If both providers fail or rate-limit, raises `ProviderUnavailableError`, records `AI_UNAVAILABLE` in `AuditEventModel`, and activates deterministic forensic pipeline. Zero fake AI text generated.
- **Real Health Check (`router.py:get_system_llm_status`)**:
  - Probes live endpoints with `max_tokens=1` minimal payloads to calculate actual network latency without exposing API keys.
- **Agentic Multi-Round Tool Calling (`routes.py`, `investigator.py`)**:
  - `POST /api/investigations/{id}/agent/chat` executes a multi-round (up to 4 rounds) reasoning loop sending 12 structured `LLM_TOOL_SCHEMAS`.
  - Dispatches tool invocations through `ToolGateway.execute_tool()`, feeds results back to LLM, and persists `AgentStepModel` and `AgentRunModel` in SQLite.

### F. Authentication & Security Hardening (`securemailscope/core/security.py`)
- **Password Hashing**: PBKDF2-HMAC-SHA256 with 600,000 iterations and unique per-password cryptographically random salts.
- **Session Tokens**: Cryptographically random opaque tokens, hashed before storage, with TTL expiry.
- **Session Revocation**: In-memory thread-safe blacklist immediately invalidates session tokens upon `POST /api/auth/logout`.

---

## 3. What Was Repaired & Implemented

| Issue Identified | Resolution Implemented | File(s) Modified |
| :--- | :--- | :--- |
| SHAP explainability was missing | Integrated `shap.TreeExplainer` for multiclass XGBoost with top-5 directionality | `securemailscope/ml/model.py` |
| LLM health check was returning static config | Implemented real HTTP ping probes with latency measurement | `backend/llm/router.py` |
| Dead code `_deterministic_fallback_chat()` | Removed dead fallback code to guarantee no fake AI generation | `backend/llm/router.py` |
| Agent chat did not execute tool schemas | Rewrote `/agent/chat` to full 4-round agentic tool calling loop | `securemailscope/api/routes.py` |
| Duplicate `/all-evidence` route | Removed duplicate route, normalized query parameter filtering | `securemailscope/api/routes.py` |
| Missing EML forensic parser | Created full EML parser extracting headers, MIME, and attachments | `securemailscope/forensics/email_parser.py` |
| Hardcoded fixture text in UI | Replaced `"Analyze scenario fixture: ..."` with `"Analyze capture: ..."` | `securemailscope/web/static/app-workstation.js` |
| Missing token revocation on logout | Added token revocation blacklist returning 401 post-logout | `securemailscope/core/security.py`, `auth.py` |
| Missing CLI `verify-ledger` command | Added `verify-ledger` checking hash chains, mutations, and citations | `securemailscope/cli.py` |
| NVIDIA primary model rate-limited/404 | Updated model to `meta/llama-3.2-11b-vision-instruct` (passed 100%) | `.env`, `securemailscope/core/config.py` |
| Gemini fallback model quota exhausted | Updated model to `gemini-3.6-flash` (passed 100% with tool calls) | `.env`, `securemailscope/core/config.py` |

---

## 4. Host Tool & External Dependency Status

| Tool / Dependency | Host Status | Resolution / Graceful Degradation |
| :--- | :--- | :--- |
| `tshark` | **Installed** (`/usr/bin/tshark`, v4.6.8) | Full deep packet dissection active |
| `capinfos` | **Installed** (`/usr/bin/capinfos`, v4.6.8) | Exact packet framing validation active |
| `openssl` | **Installed** (`/usr/bin/openssl`, v3.5.8) | Cryptographic certificate validation active |
| `zeek` | *Not Installed* | System marks Zeek as `UNAVAILABLE`; Scapy handles L7 |
| `tcpflow` | *Not Installed* | Native `TCPReconstructionEngine` handles stream reassembly |
| `clamav` | *Not Installed* | Optional tool; attachment triage flags suspicious extensions |
| `NVIDIA NIM API` | **Verified Online** | `healthy=True`, latency ~610ms, structured tool calling verified |
| `Google Gemini API` | **Verified Online** | `healthy=True`, latency ~870ms, structured tool calling verified |
