# SecureMailScope
## Agentic Cryptographic Forensics for Secure Email Communications

**SIH 2026 Problem Statement:** SIH26159  
**Organization:** National Technical Research Organisation (NTRO)  
**Category:** Software | **Theme:** Blockchain & Cybersecurity  

---

## 1. Executive Summary

**SecureMailScope** is an **evidence-first, AI-assisted cryptographic forensic platform** designed to assess the security posture of SMTP, IMAP, and POP3 communications from passive network captures (PCAP/PCAPNG).

The platform reconstructs email communication sessions from PCAPs and deterministically analyzes:
- **Protocol State Machines**: SMTP, IMAP, and POP3 state machines, transitions, and cleartext credential detection.
- **STARTTLS Negotiation**: 10-state machine tracing `CONNECTED` &rarr; `GREETING` &rarr; `CAPABILITY/EHLO` &rarr; `STARTTLS_ADVERTISED` &rarr; `STARTTLS_REQUESTED` &rarr; `STARTTLS_ACCEPTED` &rarr; `TLS_NEGOTIATION` &rarr; `ENCRYPTED` &rarr; `PLAINTEXT_FALLBACK` &rarr; `FAILED`.
- **Capture Completeness**: TCP sequence gap analysis, retransmissions, truncation penalties, and packet-loss confidence scoring.
- **TLS Handshake Forensics**: Version negotiation (TLS 1.0 to 1.3), cipher suites, Perfect Forward Secrecy (PFS), ALPN, and SNI.
- **Observable X.509 Certificates**: Public key strengths, expiration, SAN matching, self-signed detection, and chain analysis.
- **Honest TLS 1.3 Observability**: Explicit `NOT_OBSERVABLE` status for post-ServerHello encrypted certificate handshakes (never manufactures synthetic certs).
- **Machine Learning Layer**: Gradient-boosted tree classifier (XGBoost) evaluating 15 cryptographic features with explainable SHAP attributions.
- **Stateful Investigation Agent**: Explicit state machine (`OBSERVE` &rarr; `HYPOTHESIZE` &rarr; `PLAN` &rarr; `SELECT TOOL` &rarr; `EXECUTE` &rarr; `STORE EVIDENCE` &rarr; `CORRELATE` &rarr; `RE-EVALUATE` &rarr; `VERIFY` &rarr; `VERDICT`).
- **No Evidence &rarr; No Finding Gatekeeper**: Findings strictly require existing evidence IDs with verified provenance chains.

---

## 2. Architecture & Dependency Inversion

SecureMailScope enforces a strict one-way dependency chain:
```
PCAP / PCAPNG Capture
       ↓
Deterministic Forensic Engines (TShark, Capinfos, OpenSSL, Scapy, Parsers)
       ↓
Evidence Ledger & Database (SQLite / SQLAlchemy / Alembic)
       ↓
Machine Learning (XGBoost) & Deterministic Crypto Rules
       ↓
Stateful Investigation Agent
       ↓
LLM Router (Priority 1: NVIDIA NIM Kimi K3 | Priority 2: Gemini | Priority 3: Deterministic Fallback)
```

> **CRITICAL GUARANTEE:** The LLM reasons *over* established facts. It never creates, hallucinates, or modifies evidence. When external LLM API keys are missing or offline, the entire forensic engine, finding validator, and reporting operate with zero loss of forensic accuracy.

---

## 3. Tech Stack & External Credentials

### External Credentials (Exactly Three):
1. **NVIDIA NIM** (`NVIDIA_API_KEY`): Primary LLM (`moonshotai/kimi-k3`) via `https://integrate.api.nvidia.com/v1/chat/completions`.
2. **Google Gemini** (`GEMINI_API_KEY`): Fallback LLM (`gemini-1.5-flash`).
3. **Tavily** (`TAVILY_API_KEY`): External OSINT / web intelligence search (`intel.tavily_search`) strictly tagged as `EXTERNAL_INTELLIGENCE`.

### Backend & Data Science:
- **FastAPI & Uvicorn**: Async REST API and Server-Sent Events (SSE) streaming.
- **SQLAlchemy 2.0 & Alembic**: Database models, migrations, and PostgreSQL portability.
- **Scapy & System Binaries**: `tshark`, `capinfos`, `openssl` for deep packet inspection.
- **XGBoost & Scikit-learn**: Tabular cryptographic risk classification.
- **ReportLab & Jinja2**: Multi-format audit reporting (JSON, HTML, PDF).

---

## 4. Directory Structure

```
SecureMailScope/
├── backend/
│   └── llm/                  # Provider Abstraction Layer
│       ├── base.py           # Abstract LLMProvider interface
│       ├── nvidia.py         # NVIDIA NIM (moonshotai/kimi-k3) provider
│       ├── gemini.py         # Google Gemini fallback provider
│       ├── router.py         # Priority LLM router & audit trail
│       ├── schemas.py        # Chat & completion schemas
│       └── exceptions.py     # Custom error hierarchy
├── securemailscope/
│   ├── agent/                # Real stateful agent & hypothesis engine
│   ├── api/                  # FastAPI routes & SSE event bus
│   ├── core/                 # Config & exception hierarchy
│   ├── db/                   # SQLAlchemy models & session factory
│   ├── evidence/             # Evidence ledger & finding verification gate
│   ├── forensics/            # Scapy, TShark, STARTTLS, TLS & X.509 engines
│   ├── ml/                   # XGBoost risk model & benchmark engine
│   ├── reports/              # Deterministic JSON, HTML & PDF generators
│   └── tools/                # Allowlisted Tool Gateway & Tavily tool
├── demo/                     # Standalone demo scenarios
│   ├── clean/                # Valid TLS 1.2 SMTP
│   ├── starttls-anomaly/     # STARTTLS accepted -> cleartext fallback
│   ├── weak-crypto/          # Deprecated TLS 1.0 + RC4
│   ├── incomplete-capture/   # Truncated capture (inconclusive)
│   └── tls13/                # TLS 1.3 encrypted cert limitation
├── migrations/               # Alembic database migrations
├── samples/                  # Pre-packaged test captures
├── tests/                    # 29 unit & integration tests
├── .env.example              # Environment configuration template
├── requirements.txt          # Frozen Python dependencies
└── README.md
```

---

## 5. Local Setup & Quick Start

### 1. Environment Setup
```bash
# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
```

### 2. Database Migrations
```bash
# Run database schema migrations
alembic upgrade head
```

### 3. Generate Demonstration Samples & Fixtures
```bash
python -m securemailscope.cli generate-samples
PYTHONPATH=. python securemailscope/forensics/generate_demo_fixtures.py
```

### 4. Launch Web Investigation Console
```bash
python -m securemailscope.cli serve --host 127.0.0.1 --port 8000
```
Open **`http://127.0.0.1:8000`** in your browser.

---

## 6. API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/health` | Health check and platform version |
| `GET` | `/api/system/tools` | Discovers installed binaries (`tshark`, `capinfos`, `zeek`, `openssl`) |
| `GET` | `/api/system/llm/status` | Real configuration and health of NVIDIA, Gemini, and Tavily |
| `GET` | `/api/ml/metrics` | Empirical accuracy, precision, recall, F1, and confusion matrices |
| `POST` | `/api/investigations` | Ingests a capture and executes the full agent investigation |
| `GET` | `/api/investigations/{id}` | Fetches investigation dossier, posture score, and sessions |
| `GET` | `/api/investigations/{id}/evidence` | Returns verified evidence items from the ledger |
| `GET` | `/api/investigations/{id}/findings` | Returns validated cryptographic findings |
| `GET` | `/api/investigations/{id}/sessions` | Returns reconstructed TCP conversations and streams |
| `GET` | `/api/investigations/{id}/timeline` | Returns chronological timeline audit events |
| `GET` | `/api/investigations/{id}/replay` | Deterministic replay of agent steps, hypotheses, and evidence without re-executing tools |
| `POST` | `/api/investigations/{id}/agent/chat` | Conversational investigation reasoning grounded strictly in evidence |
| `POST` | `/api/investigations/{id}/agent/step` | Manually triggers an individual state-machine tool step |
| `GET` | `/api/investigations/{id}/events` | Real-time Server-Sent Events (SSE) stream |
| `GET` | `/api/investigations/{id}/reports/json` | Downloads machine-readable JSON report |
| `GET` | `/api/investigations/{id}/reports/html` | Downloads standalone HTML forensic report |
| `GET` | `/api/investigations/{id}/reports/pdf` | Downloads publication-ready audit PDF report |

---

## 7. Running Tests

Execute the comprehensive 36-test verification suite:
```bash
pytest tests/ -v
```

Tests validate:
- **LLM Priority Routing**: NVIDIA NIM (priority 1) &rarr; Gemini (priority 2) &rarr; Local Deterministic Reasoner (priority 3).
- **Tavily Tool & External Intel**: Permission gating, strict `EXTERNAL_INTELLIGENCE` provenance tagging.
- **Tool Gateway**: 21-tool allowlisting, JSON schema validation, malicious argument rejection.
- **Evidence & Finding Gatekeeper**: "No Evidence &rarr; No Finding", cross-investigation rejection, provenance chains.
- **Protocol Forensics**: SMTP/IMAP/POP3 STARTTLS downgrade attacks, weak ciphers (RC4, 3DES), deprecated TLS (TLS 1.0/1.1).
- **TLS 1.3 Limitation**: Honest `NOT_OBSERVABLE` certificate status (never manufactures synthetic certs).
- **Capture Completeness**: TCP sequence gap analysis, confidence penalties for truncated captures.
- **Security Hardening**: Path traversal rejection, PCAP magic bytes validation, SSRF protection against internal IPs.
- **Contradiction Detection**: Explicit identification and reconciliation of rule vs ML divergence and completeness anomalies.
- **Deterministic Replay**: Ordered step replay without re-running forensic tools.
- **Multi-Format Reports**: Verifiable JSON, HTML, and PDF reports.
