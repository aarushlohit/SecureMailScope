# SecureMailScope — Authentication & Access Control

## 1. Security Design
SecureMailScope implements a defense-in-depth authentication framework:
- **Password Hashing**: PBKDF2-HMAC-SHA256 with 600,000 iterations and 16-byte cryptographically secure random salts generated via `secrets.token_bytes()`.
- **Constant-Time Verification**: Verification utilizes `hmac.compare_digest()` to prevent side-channel timing attacks.
- **Session Tokens**: Cryptographically signed HMAC-SHA256 bearer tokens containing a session ID.
- **Dual Support**: Supports both `Authorization: Bearer <token>` HTTP headers (for API clients/CLI) and `securemailscope_token` HTTP-only cookies (for browser sessions).
- **Durable Session Revocation**: The `POST /api/auth/logout` endpoint persists revocation in the `auth_sessions` database table. Subsequent requests using the revoked token receive `HTTP 401 Unauthorized`, including after a new database session or application process restart.
- **Token Storage**: Raw bearer tokens are not stored in the database. The session table stores a SHA-256 token hash, session ID, user ID, timestamps, and optional user-agent metadata.

## 2. API Endpoints

### 2.1 User Registration
`POST /api/auth/signup`
```json
{
  "email": "analyst@soc.gov.in",
  "password": "ComplexPassword123!",
  "full_name": "Cyber Defense Analyst"
}
```
- Rejects duplicate email addresses with `HTTP 400` or `HTTP 409`.
- Enforces password length of at least 8 characters.
- Returns user profile, access token, and sets HTTP-only cookie.

### 2.2 User Login
`POST /api/auth/login`
```json
{
  "email": "analyst@soc.gov.in",
  "password": "ComplexPassword123!"
}
```
- Validates credentials against PBKDF2 hash.
- Returns generic `"Invalid email or password."` on failure to prevent user enumeration attacks.

### 2.3 Current Session Profile
`GET /api/auth/me`
- Requires valid session token.
- Returns authenticated analyst details and role.
- Validates token signature, token expiry, persisted session existence, persisted session expiry, revocation state, and active user state.

### 2.4 Session Logout & Revocation
`POST /api/auth/logout`
- Revokes the persisted session by setting `revoked_at` and clears the browser session cookie.

## 3. Investigation Ownership
- Every investigation record is accessed through an authenticated owner context.
- Protected investigation, evidence, finding, session, replay, SSE, and report endpoints scope database lookups by both `investigation_id` and the authenticated `user_id`.
- Cross-user resource access is hidden with `HTTP 404` to avoid leaking resource existence or metadata.
- Global evidence and finding views require authentication and are filtered to the caller's owned investigations.
- See `docs/route-authorization-matrix.md` for the audited route matrix.
