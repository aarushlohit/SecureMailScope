# SecureMailScope — Security Hardening & Isolation Controls

## 1. Threat Model & Defensive Controls
As a forensic platform handling untrusted network traffic and malicious email artifacts, SecureMailScope enforces strict isolation boundaries:

### 1.1 Input Ingestion Controls
- **Extension Allowlist**: Only `.pcap`, `.pcapng`, `.cap`, and `.eml` files permitted.
- **Magic-Byte Signature Verification**: Rejects spoofed extensions (e.g. fake PNG or shell scripts renamed to `.pcap`).
- **Path Traversal Protection**: Enforces `Path(filename).name` sanitization, blocking directory traversal sequences (`../`, `..\\`).
- **File Size Quota**: Strictly limits uploaded artifacts to 50 MB to prevent resource exhaustion attacks.

### 1.2 Tool Execution Sandboxing
- **Zero Shell Execution**: All external commands (e.g. `tshark`, `capinfos`, `openssl`) execute via `subprocess.run(shell=False)` with explicit argument vectors.
- **Per-Tool Timeouts**: Enforces execution deadlines between 10.0s and 30.0s via `asyncio.wait_for` / `subprocess(timeout=...)`.
- **Parameter Validation**: Tool arguments are validated against strict schema types; command injection characters are treated as literal filenames or rejected.

### 1.3 Database Referential Integrity
- Complete referential integrity enforced via SQLAlchemy models.
- The `python -m securemailscope.cli validate-db` utility verifies:
  - Zero duplicate user accounts.
  - Zero orphan investigations.
  - Zero orphan evidence records.
  - Zero orphan findings.
  - Zero findings without evidence (enforcing "No Evidence -> No Finding").
  - Zero cross-investigation evidence citations.
  - Zero orphan forensic sessions.

### 1.4 LLM Security & Guardrails
- **Evidence-Constrained Prompts**: LLM system prompts strictly require citing only listed `Evidence IDs`.
- **Prompt Injection Defense**: Tool outputs are JSON-serialized and encapsulated in `ChatMessage(role="tool")`.
- **API Key Protection**: API keys are never exposed in `/api/system/llm/status`, reports, client bundles, or logs.
