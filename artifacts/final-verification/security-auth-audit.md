# SecureMailScope Security Audit

## 1. Authentication & Authorization Matrix

| Route | Method | Auth Required | Ownership Enforced | Status |
|---|---|---|---|---|
| `/health` | GET | No | N/A | SECURE |
| `/system/tools` | GET | No | N/A | VULNERABLE (Missing Auth) |
| `/system/llm/status` | GET | No | N/A | VULNERABLE (Missing Auth) |
| `/ml/metrics` | GET | No | N/A | VULNERABLE (Missing Auth) |
| `/ml/benchmark` | GET | No | N/A | VULNERABLE (Missing Auth) |
| `/intel/query` | GET | No | N/A | VULNERABLE (Missing Auth, SSRF Risk) |
| `/samples` | GET | No | N/A | VULNERABLE (Missing Auth) |
| `/all-findings` | GET | Yes | Yes (Filtered) | SECURE |
| `/all-evidence` | GET | Yes | Yes (Filtered) | SECURE |
| `/investigations` | POST | Yes | Yes | SECURE |
| `/investigations` | GET | Yes | Yes (Filtered) | SECURE |
| `/investigations/{investigation_id}` | GET | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/artifacts` | POST | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/analyze` | POST | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/replay` | GET | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/evidence` | GET | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/findings` | GET | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/sessions` | GET | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/timeline` | GET | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/agent/chat` | POST | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/agent/step` | POST | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/events` | GET | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/reports/json` | GET | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/reports/html` | GET | Yes | Yes | SECURE |
| `/investigations/{investigation_id}/reports/pdf` | GET | Yes | Yes | SECURE |
| `/auth/signup` | POST | No | N/A | SECURE |
| `/auth/login` | POST | No | N/A | SECURE |
| `/auth/logout` | POST | Yes | N/A | SECURE |
| `/auth/me` | GET | Yes | N/A | SECURE |
| `WS /ws/{investigation_id}` | GET (WS) | Yes (Manual) | Yes (Manual) | SECURE |

## 2. Specific Vulnerabilities Identified

1. **Unauthenticated Endpoints:**
   - Several endpoints are completely open and do not require `Depends(get_current_user)`:
     - `/intel/query` (High Risk: exposes server to abuse via open OSINT/DNS requests)
     - `/system/tools` (Information Disclosure)
     - `/system/llm/status` (Information Disclosure)
     - `/ml/metrics` and `/ml/benchmark`
     - `/samples`

2. **CORS Misconfiguration:**
   - Location: `securemailscope/api/app.py` line 45
   - The application combines `allow_origins=["*"]` with `allow_credentials=True`. This is widely considered insecure and most modern browsers will block this explicitly. It exposes the API to Cross-Origin attacks.

3. **Data Leaks & Ownership Checks:**
   - List endpoints (`/all-findings`, `/all-evidence`, `/investigations`) properly filter data down to the `current_user.user_id`. (SECURE)
   - Object-level endpoints all properly enforce `require_owned_investigation_model`. (SECURE)
   - Report generation endpoints all verify ownership. (SECURE)

4. **WebSockets:**
   - WebSockets in `app.py` correctly perform token decoding and verify `AuthSessionModel` and `InvestigationModel` ownership manually before accepting the connection. (SECURE)

5. **Token Handling and Passwords:**
   - Password hashing uses 600,000 iterations of PBKDF2 with HMAC-SHA256 and constant-time comparisons. (SECURE)
   - Tokens use a properly generated ephemeral key if not provided, and session invalidations correctly track both time, revoked status, and matching token hashes in the DB. (SECURE)

## 3. Recommendations
- Implement authentication on `/intel/query` and the `/system/*` endpoints.
- Update `CORSMiddleware` configuration to specify exact origins rather than `*` when `allow_credentials` is `True`.
