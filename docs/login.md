# Login and session API

All endpoints use `/api/v1/auth` and the project's `ApiResponse`: `success`, optional error `code`, `message`, `messageFa`, `data`, and UTC `timestamp`. No `ApiMessage` catalog is used. Token responses and errors have `Cache-Control: no-store`.

## Endpoints

| Method/path | JSON body | Result |
| --- | --- | --- |
| `POST /login-password` | `{"identifier":"user@example.com","password":"..."}` | Token pair, or an OTP challenge when password OTP is enabled |
| `POST /login-otp-email` | `{"email":"user@example.com"}` | Generic OTP challenge response |
| `POST /login-otp-phone` | `{"phone":"09123456789"}` | Generic SMS challenge response |
| `POST /verify` | `{"mfaToken":"...","otp":"012345"}` | Consumes the login challenge and issues a token pair |
| `POST /refresh` | `{"refreshToken":"..."}` | Atomically consumes the refresh token and returns its replacement plus a new access token |
| `POST /logout` | `{"refreshToken":"..."}` | Idempotently revokes the entire session, including when given a consumed ancestor |
| `POST /logout-all` | None; `Authorization: Bearer <accessToken>` required | Revokes all sessions for the verified JWT subject |

The first six endpoints are explicitly public. `/logout-all` requires a valid access token and active session; there is no public `/auth/**` wildcard. Refresh tokens are credentials and are sent in the JSON body, never a URL. The API does not set authentication cookies.

Request aliases `refresh_token`, `mfa_token`, and `mfa` are accepted for the corresponding camelCase fields. Responses use camelCase data fields. Emails are stripped and lowercased. Iranian local, `0098` and `+98` phone variants normalize to E.164 `+989…`; other international phone numbers must already be E.164. Passwords are never trimmed; bcrypt inputs exceeding 72 UTF-8 bytes are rejected rather than silently truncated. Raw bcrypt and Spring `{bcrypt}` hashes are supported.

Successful password/OTP login:

```json
{
  "success": true,
  "message": "Logged in successfully.",
  "messageFa": "ورود با موفقیت انجام شد.",
  "data": {
    "step": "SUCCESS",
    "tokens": {
      "tokenType": "Bearer",
      "accessToken": "<JWT>",
      "accessExpiresIn": 900,
      "refreshToken": "<opaque token>",
      "refreshExpiresIn": 604800
    }
  },
  "timestamp": "2026-11-02T12:00:00Z"
}
```

OTP initiation returns `data.step = "OTP_REQUIRED"` and `data.challenge = {"mfaToken":"...","channel":"EMAIL","expiresIn":300,"resendAfter":60}`. It does not return access/refresh tokens. Refresh returns the token pair directly under `data`. Keep the latest refresh token and serialize refresh requests on the client: a second use of a consumed token revokes the session, including a concurrent duplicate or a retry after a lost successful response.

## Authentication rules

The User service remains the owner of users, bcrypt hashes, roles, status, verified contacts and credential versions. Auth uses the existing `UserGrpcClient`; no user table or raw SQL data access is added. `UNKNOWN`, pending, suspended, deactivated and credential-expired accounts cannot log in. OTP delivery requires the selected verified email/phone. OTP verification and refresh re-fetch the account and check eligibility and `credentialVersion` before issuing tokens. Verification also checks the challenge's HMAC-bound delivery destination, so changing an email/phone invalidates previously sent codes. Returned user IDs/lookup identifiers must match the requested identity. User service timeouts/unavailability return 503 without consuming the OTP or refresh token.

`AuthSettingService.getCurrent().loginEnabled` controls password login, OTP initiation and verification. Existing sessions may still refresh or log out while new logins are disabled. Notification preference flags do not disable authentication challenge delivery.

The current User contract has no per-user MFA flag. `AUTH_PASSWORD_OTP_REQUIRED=true` requires an OTP after a correct password, using the current settings' `defaultOtpChannel`; it defaults to `false`. Passwordless email/SMS OTP login remains available independently. This is a global policy for the password flow, not a substitute for a future per-account MFA enrollment policy. `IN_APP` is only selectable for the password follow-up challenge, and its destination is the user ID.

Unknown, ineligible, unverified or locked accounts receive the same OTP response and a random decoy challenge; no notification or login session is created. Password login uses a dummy bcrypt comparison for an unknown account. Client-visible password errors do not disclose whether an account exists or is disabled.

## Throttling and cooldown

Redis is required; failure to enforce a policy returns 503. Keys contain HMAC fingerprints rather than raw email/phone/IP values. Lua scripts atomically update each counter and TTL using Redis time. Defaults:

| Policy | Default |
| --- | --- |
| Requests per source IP | 60 per minute across login, verification and refresh |
| Failed password/OTP attempts | 5 within a 30-minute observation window |
| Lock duration | Starts at 1 minute; doubles for each further group of 5 failed attempts, capped at 30 minutes |
| OTP length / lifetime | 6 digits / 5 minutes |
| OTP attempts per challenge | 3; the third incorrect code deletes the challenge |
| OTP resend cooldown | 1 minute, applied to both normalized identifier and known account |

Locks apply to the identifier and, for known accounts, the user ID across email/phone aliases. A request during a lock does not extend it. Failed OTP attempts do not remove the resend cooldown. A fresh real OTP invalidates previous open login challenges for that account; resending cannot reset the account failure limit. A successful committed login clears the relevant failure counters while preserving any newer lock established by concurrent failures.

429 responses include `Retry-After` and `data.retryAfterSeconds`, rounded up to at least one second. Codes include `RATE_LIMITED`, `LOGIN_TEMPORARILY_LOCKED` and `OTP_COOLDOWN`. Invalid credentials, challenges and sessions use 401 with `INVALID_CREDENTIALS`, `INVALID_OTP` and `INVALID_REFRESH_TOKEN`. Invalid JSON/validation uses 400 `INVALID_REQUEST`; errors do not echo submitted credentials.

The app uses the servlet remote address, not raw `X-Forwarded-For`. If deployed behind a proxy, configure trusted forwarding at the ingress/server and prevent clients from reaching the upstream app directly; otherwise all clients share the proxy's IP limit. Device ID and user agent are bounded metadata, not authentication factors or hard IP/device bindings.

## Tokens and persistence

PostgreSQL stores `auth_sessions` and `refresh_tokens` through JPA entities, Spring Data repositories and JPQL. OTP challenges live only in Redis. V3 is preserved for Flyway checksum compatibility; V4 adds `is_revoked` to both tables and the refresh-token revocation timestamp, backfilling token-family revocation from existing revoked sessions. No JDBC/native query is introduced for runtime flows.

Opaque tokens contain 32 random bytes. PostgreSQL stores only SHA-256 refresh-token hashes. Redis stores OTP challenges under `auth:otp:{login}:challenge:<SHA-256(mfaToken)>`, containing the user ID, credential version, HMAC fingerprints for the identifier/destination, challenge-bound OTP HMAC, channel, expiry, attempts and state. Raw codes and raw MFA tokens are not stored. Every challenge and account latest-challenge pointer has the OTP TTL (5 minutes by default); state transitions never extend it. Tokens, codes, passwords and credential hashes are never logged. Application logs use SLF4J fluent `atInfo()/atWarn()/atError()` calls with separate `addKeyValue` fields and a human-readable message. Important auth requests record `ip_address`, `http_method`, `path`, bounded/sanitized `user_agent` and `device_id`. Domain outcomes additionally record user/session IDs when known, authentication method, OTP channel/attempt count, safe failure reason or retry duration. Unknown/expired OTP and refresh credentials, malformed input and dependency failures also record request context. Passwords, OTP values, request bodies, authorization headers and raw access/refresh/MFA tokens are never logged; identifiers use HMAC fingerprints. The servlet remote address is used, ignoring raw forwarded headers. Successful login, session creation and rotation events are emitted after the database commit. Native key/value fields are retained by the existing Logstash JSON encoder. With user approval, only `%kvp` was added to the existing Spring Boot console layout so these fields also appear in the terminal; appenders, levels and destinations are unchanged.

Refresh tokens expire after 7 days of inactivity and rotate on every refresh. A session has an absolute lifetime of 30 days, which rotation never extends. Session validity requires `is_revoked = false`, `revoked_at IS NULL`, and an absolute expiry strictly after the current time. Refresh validity additionally requires the token's own flag to be false, its revocation and consumption timestamps to be null, and its expiry strictly after the current time. Either revocation signal independently causes rejection. Revocation on logout, logout-all, refresh reuse/expiry, missing users, account changes, and scheduled cleanup marks both the session and all its refresh tokens in the same transaction, preserving existing revocation timestamps/reasons and consumption history. Expired sessions encountered during refresh are also revoked immediately. Token consumption during normal rotation remains separate from revocation so reuse can still be detected. Each session is a separate token family; concurrent sessions are allowed. Every token replacement belongs to the same family. Refresh and logout first lock the session with JPA `PESSIMISTIC_WRITE`, then read the token; the preliminary lookup reads only a session ID, avoiding stale entities before the lock. Reuse revocation commits even though the response is 401. OTP verification atomically claims its Redis challenge before issuing a session. Only one verifier can claim it. After the database transaction commits, the claim is closed; after a confirmed rollback, only its owner can release it for retry. Unknown outcomes or a crashed verifier leave it claimed until the original TTL expires; a new code can be requested after cooldown. No expiring verification lease can accidentally allow a second issuer while the first transaction is still running. Redis and PostgreSQL do not share a transaction, so this uses an atomic claim with completion callbacks. Atomic Redis failure counters delete challenges on the third incorrect code (configurable through AUTH_OTP_MAX_ATTEMPTS), and an atomic replacement script removes the previous challenge when a new one is issued. OTP state does not require a SQL table or cleanup job.

Access tokens use RS256 with the existing RSA/JWKS setup, `typ=at+jwt`, `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `token_use=access`, `sid`, `credential_version` and `roles`. The decoder pins RS256 and validates issuer, audience, type, timestamps and required claims. The filter derives `ROLE_…` authorities from signed roles and checks the active session in PostgreSQL on protected Auth requests. Logout/reuse therefore invalidates access on this service immediately. Other services that validate only JWT/JWKS continue accepting an already-issued access token until its expiry (15 minutes by default); they need their own session/revocation check for immediate invalidation. Upstream account/credential changes are rechecked at login/OTP verification/refresh, not on every protected request.

Session cleanup runs hourly (first run after one interval, then a fixed delay after each completion). Sessions whose absolute expiry is more than `AUTH_RETENTION` (default 7 days) in the past are revoked, along with every refresh token in their family, without deleting any records. Existing revocation timestamps/reasons and token consumption history are preserved; repeated runs only mark records not yet revoked. `AUTH_RETENTION` is the delay before archival revocation, not a data deletion period. Session and token history remain stored indefinitely. OTP challenges, latest-challenge pointers, locks and cooldowns expire in Redis through TTL without a scheduler.

## Configuration and notification integration

See `.env.example` for every setting. Set Redis connection variables and generate a separate secret with `openssl rand -base64 32`, supplying the result as `AUTH_OTP_SECRET` to every Auth instance. The secret must decode to at least 32 bytes; there is no production fallback. Changing it invalidates existing OTPs and resets the effective Redis fingerprints. Supply variables through the IDE/process/deployment; Spring does not automatically load `.env`.

`NotificationService.sendLoginOtp(long userId, OtpChannel channel, String destination, String code)` is intentionally empty. The login flow calls it, but actual email/SMS/in-app delivery requires the user's later integration. No RabbitMQ dependency or configuration was added. Until that integration is implemented, OTP codes are not delivered and OTP login cannot complete through a real notification channel; codes are never exposed in logs/responses as a workaround.

Apply migrations through normal Flyway startup. V4 adds `is_revoked BOOLEAN NOT NULL DEFAULT FALSE` to both `auth_sessions` and `refresh_tokens`, plus the nullable `refresh_tokens.revoked_at` column, without deleting session or token history. Existing session revocations are backfilled into the flags and their complete token families. V3 is unchanged. The existing logging appenders, levels and destinations are preserved; the console layout additionally displays native key/value fields.

## Verification

Unit tests cover token claims/signatures, identifier normalization, OTP hashing and standard security responses. `LoginFlowIntegrationTest` uses real PostgreSQL/JPA transactions and Redis scripts, with the User service and notification boundary replaced locally for tests. It covers concurrent OTP/refresh consumption, committed reuse revocation, logout, lockout, resend, expiry, credential changes, unavailable dependencies and safe error responses.

Set `AUTH_TEST_DATABASE_URL`, `AUTH_TEST_DATABASE_PASSWORD` and `AUTH_TEST_REDIS_PORT` to disposable local instances, then run:

```shell
./mvnw -Dtest=LoginFlowIntegrationTest test
```

The integration test deletes auth state in those disposable stores; it is skipped without `AUTH_TEST_DATABASE_URL`. The existing `AuthApplicationTests` additionally needs the usual database, gRPC and `AUTH_OTP_SECRET` environment settings. Existing advisory-lock tests run when `AUTH_LOCK_TEST_URL` / `AUTH_LOCK_TEST_PASSWORD` point to the disposable database.

Design references: [RFC 9700 refresh-token protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14), [OWASP authentication controls](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [Spring Data JPA locking](https://docs.spring.io/spring-data/jpa/reference/jpa/locking.html), [Spring Redis scripting](https://docs.spring.io/spring-data/redis/reference/redis/scripting.html).
