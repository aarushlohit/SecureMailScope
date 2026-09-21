# SecureMailScope Route Authorization Matrix

Protected investigation resources use `get_current_user` and `require_owned_investigation_model`.
Resource lookups are scoped by `investigation_id` and authenticated `user_id`; cross-user access returns `404`.

| Method | Route | Auth | Resource ID | Ownership Check | Missing Auth | Cross User | Data Path |
| --- | --- | --- | --- | --- | --- | --- | --- |
| GET | `/api/health` | No | None | None | 200 | N/A | Public system status |
| GET | `/api/system/tools` | No | None | None | 200 | N/A | Tool discovery |
| GET | `/api/system/llm/status` | No | None | None | 200 | N/A | Provider health, no secrets |
| GET | `/api/ml/metrics`, `/api/ml/benchmark` | No | None | None | 200 | N/A | Benchmark engine |
| GET | `/api/intel/query` | No | None | None | 200 | N/A | Controlled DNS/OSINT tools |
| GET | `/api/samples` | No | Sample name list | Path constrained to samples | 200 | N/A | Samples directory |
| POST | `/api/auth/signup` | No | None | Creates user-derived session | 200/400 | N/A | Auth service |
| POST | `/api/auth/login` | No | None | Creates user-derived session | 200/401 | N/A | Auth service |
| GET | `/api/auth/me` | Yes | Session | `auth_sessions.token_hash`, `user_id`, expiry, revocation | 401 | N/A | Auth service |
| POST | `/api/auth/logout` | Yes | Session | Persists `revoked_at` by session/token hash | 401 | N/A | Auth service |
| GET | `/api/investigations` | Yes | Current user | Lists only DB rows with current `user_id` | 401 | Hidden | Ledger filtered by DB ownership |
| POST | `/api/investigations` | Yes | Current user | Ignores client owner IDs; stores current `user_id` | 401 | N/A | Upload/sample plus agent |
| GET | `/api/investigations/{investigation_id}` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then ledger |
| POST | `/api/investigations/{investigation_id}/artifacts` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then upload |
| POST | `/api/investigations/{investigation_id}/analyze` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then agent |
| GET | `/api/investigations/{investigation_id}/replay` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then agent steps |
| GET | `/api/investigations/{investigation_id}/evidence` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then ledger |
| GET | `/api/all-evidence` | Yes | Optional `investigation_id` | Filters to current user's investigations; foreign ID returns 404 | 401 | 404/hidden | DB-owned ID set then ledger |
| GET | `/api/all-findings` | Yes | Current user | Filters to current user's investigations | 401 | Hidden | DB-owned ID set then ledger |
| GET | `/api/investigations/{investigation_id}/findings` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then ledger |
| GET | `/api/investigations/{investigation_id}/sessions` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then capture parser |
| GET | `/api/investigations/{investigation_id}/timeline` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then ledger |
| POST | `/api/investigations/{investigation_id}/agent/chat` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then LLM/tool loop |
| POST | `/api/investigations/{investigation_id}/agent/step` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then gateway |
| GET | `/api/investigations/{investigation_id}/events` | Yes | `investigation_id` | DB query includes current `user_id` before subscription | 401 | 404 | DB gate then SSE bus |
| GET | `/api/investigations/{investigation_id}/reports/json` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then reporter |
| GET | `/api/investigations/{investigation_id}/reports/html` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then reporter |
| GET | `/api/investigations/{investigation_id}/reports/pdf` | Yes | `investigation_id` | DB query includes current `user_id` | 401 | 404 | DB gate then reporter |
