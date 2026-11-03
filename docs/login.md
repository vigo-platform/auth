# Login and session API

All endpoints use `/api/v1/auth` and the project's `ApiResponse`: `success`, optional error `code`, `message`, `messageFa`, `data`, and UTC `timestamp`. No `ApiMessage` catalog is used. Token responses and errors have `Cache-Control: no-store`.

## Endpoints

| Method/path | JSON body | Result |
| --- | --- | --- |
| `POST /register/initiate` | `{"identifier":"new@example.com"}` or a mobile number | Registration OTP challenge; see [registration](registration.md) |
| `POST /register/verify` | `{"mfaToken":"...","otp":"012345"}` | A temporary `registrationToken`; no account or login tokens |
| `POST /register/complete` (alias `/register`) | `{"registrationToken":"...","password":"...","firstName":"...","lastName":"..."}` | HTTP 201 with `userId` and User-owned `status`; names optional; no tokens |
| `POST /login-password` | `{"identifier":"user@example.com","password":"..."}` | Token pair, OTP challenge, or password change continuation |
| `POST /login-otp-email` | `{"email":"user@example.com"}` | Generic OTP challenge response |
| `POST /login-otp-phone` | `{"phone":"09123456789"}` | Generic SMS challenge response |
| `POST /verify` | `{"mfaToken":"...","otp":"012345"}` | Consumes the login challenge and issues a token pair or password change continuation |
| `POST /password/expired/complete` | `{"passwordChangeToken":"...","newPassword":"..."}` | Updates an expired password and completes sign-in when the account still qualifies |
| `POST /refresh` | `{"refreshToken":"..."}` | Atomically consumes the refresh token and returns its replacement plus a new access token |
| `POST /logout` | None. Requires `Authorization: Bearer <accessToken>` | Revokes the session identified by the verified JWT `sid` and all its refresh tokens |
| `POST /logout-all` | None. Requires `Authorization: Bearer <accessToken>` | Revokes all sessions for the verified JWT subject |

Registration, login, OTP verification, expired-password completion and refresh are explicitly public. Both logout endpoints require a valid access token. Logout revokes refresh tokens. An issued access token stays valid until its expiration and can still authenticate requests, including logout. Send refresh tokens in the JSON body of `/refresh`. The API does not set authentication cookies.

Request aliases `refresh_token`, `mfa_token`, and `mfa` are accepted for the corresponding camelCase fields. Responses use camelCase data fields. Emails are stripped and lowercased. Iranian local, `0098` and `+98` phone variants normalize to E.164 `+989…`; other international phone numbers must already be E.164. Passwords are never trimmed; bcrypt inputs exceeding 72 UTF-8 bytes are rejected rather than silently truncated. Raw bcrypt and Spring `{bcrypt}` hashes are supported.

User responses may contain the equivalent Iranian local `09…` phone format.
Auth compares normalized identities and supports a local-format lookup fallback
as described in [the gRPC integration](user-grpc.md). All input variants share
one identifier cooldown. Cooldown alone does not prove a challenge was created:
unknown or ineligible accounts deliberately get the same response without a
Redis challenge. `otp_request_accepted` audit events record the safe skip reason.

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

The User service remains the owner of users, bcrypt hashes, roles, status, verified contacts and credential versions. Auth uses the existing `UserGrpcClient`; no user table or raw SQL data access is added. `UNKNOWN`, pending, suspended and deactivated accounts cannot log in. An active account with expired credentials must verify all required login factors before receiving a password change continuation. OTP delivery requires the selected verified email/phone. OTP verification and refresh re-fetch the account and check eligibility and `credentialVersion` before issuing tokens. Verification also checks the challenge's stored delivery destination, so changing an email/phone invalidates previously sent codes. Returned user IDs/lookup identifiers must match the requested identity. User service timeouts/unavailability return 503 without consuming the OTP or refresh token.

When refresh detects a credential-version mismatch for an otherwise eligible account,
it rejects the request and revokes only sessions and refresh tokens with credential
versions older than the User snapshot. Sessions using the current or a newer version
remain valid, so an old device cannot log out a session created after a password
change. An ineligible account still causes all of that user's sessions and refresh
tokens to be revoked, regardless of credential version.

`AuthPolicyService` enforces `loginEnabled` for password login, OTP initiation and
verification. Each channel's `*NotificationEnabled` switch gates both creation and
verification of its authentication challenges. A disabled channel returns 503
`OTP_CHANNEL_DISABLED` and never falls back to password-only login. Existing sessions
may still refresh or log out while new logins/channels are disabled. See
[runtime settings](auth-settings.md) for propagation and default-channel behavior.

`registerEnabled` independently gates every registration stage with 503
`REGISTRATION_DISABLED`. Registration now requires an email/SMS OTP before account
creation. Channel switches, identifier cooldown/failure policies and the IP limit
also apply. Only the contact proven by registration can reach `CreateUser`; User's
current deployment creates the account active and verified. Auth still does not
issue login tokens or add a verification/activation RPC. See [registration](registration.md)
for the new request bodies, Redis state, delivery integration and retry behavior.

User contract 3.1.0 supplies the per-account `two_factor_enabled` flag. After a correct password, Auth requires OTP when this flag is `true` **or** `AUTH_PASSWORD_OTP_REQUIRED=true`. The global flag defaults to `false` and cannot disable an account's two-factor policy. Both policies use the current settings' `defaultOtpChannel`. No session or access/refresh token is created before successful OTP verification. If the selected channel has no verified destination, login fails with the generic `INVALID_CREDENTIALS` response; it never falls back to password alone. `IN_APP` is only selectable for the password follow-up challenge, and its destination is the user ID.

Passwordless email/SMS OTP login is available only to accounts without per-account two-factor authentication. For enrolled accounts these endpoints return the same generic decoy response used for unknown accounts, without sending a code or revealing enrollment. Clients must begin with `/login-password` and submit the returned challenge to `/verify`. A server-owned `passwordVerified` field in Redis records whether the challenge followed password verification. `/verify` re-fetches the account and rejects a passwordless challenge if two-factor authentication was enabled after issuance. Enrollment itself is managed by User; this contract adds no enrollment endpoint.

Unknown, ineligible, unverified, locked or two-factor-enrolled accounts receive the same passwordless OTP response and a random decoy challenge; no notification or login session is created. Password login uses a dummy bcrypt comparison for an unknown account. Client-visible password errors do not disclose whether an account exists or is disabled.

Two-factor audit events use the existing structured logging setup. `login_second_factor_required` records the account/global policy flags and selected channel after password verification; `otp_challenge_created`, `otp_verification_failed`, `otp_rejected` and committed `login_success` distinguish `PASSWORD_OTP` from passwordless `OTP`. A missing verified channel uses reason `otp_channel_unavailable`; a passwordless request/challenge blocked by enrollment uses `password_verification_required`. No password, hash, OTP, destination or raw token is logged.

Deploy User 3.1.0 support before this Auth version: omitted proto3 booleans default to `false`. Roll out this Auth version across all instances together, since older instances do not enforce the new flag. Existing Redis challenges without `passwordVerified` are treated as having no password proof: two-factor accounts must start a fresh password login; accounts without two-factor authentication can complete their existing OTP challenges. No SQL migration or Redis flush is required. Existing sessions retain their refresh behavior; enabling two-factor authentication controls new logins and does not by itself revoke sessions.

## Expired credentials after authentication

After a correct password in password-only login, a correct password and OTP in
2FA, or a correct OTP in passwordless login, Auth checks credential expiry.
If expired, it returns HTTP 200 with
`data.step = "PASSWORD_CHANGE_REQUIRED"` and
`data.passwordChange = {"passwordChangeToken":"...","expiresIn":300}`.
No access or refresh token is issued at this step. Submit the new password and
the one-time token to `POST /password/expired/complete`. Auth rechecks the
account after User updates the password and issues a token pair only when the
account and saved login proof still meet current login policy. If the password
was updated and sign-in must restart, the response step is
`PASSWORD_UPDATED_LOGIN_REQUIRED`. Refresh continues to reject expired
credentials. See [password lifecycle](password-lifecycle-design.md).

## Throttling and cooldown

Redis is required; failure to enforce a policy returns 503. Keys use readable, namespaced email/phone/IP/account values; no cryptographic hash or HMAC is used for Redis keys or values. Lua scripts atomically update each counter and TTL using Redis time. The rate limits, lock escalation, cooldowns and expiry rules are unchanged by the readable-key change. Defaults:

| Policy | Default |
| --- | --- |
| Requests per source IP | 60 per minute across registration, login, verification and refresh |
| Failed password/OTP attempts | 5 within a 30-minute observation window |
| Lock duration | Starts at 1 minute; doubles for each further group of 5 failed attempts, capped at 30 minutes |
| OTP length / lifetime | 6 digits / 5 minutes |
| OTP attempts per challenge | 3; the third incorrect code deletes the challenge |
| OTP resend cooldown | 1 minute, applied to both normalized identifier and known account |

Locks apply to the identifier and, for known accounts, the user ID across email/phone aliases. A request during a lock does not extend it. Failed OTP attempts do not remove the resend cooldown. A fresh real OTP invalidates previous open login challenges for that account; resending cannot reset the account failure limit. A successful committed login clears the relevant failure counters while preserving any newer lock established by concurrent failures.

429 responses include `Retry-After` and `data.retryAfterSeconds`, rounded up to at least one second. Codes include `RATE_LIMITED`, `LOGIN_TEMPORARILY_LOCKED` and `OTP_COOLDOWN`. Invalid credentials, challenges and sessions use 401 with `INVALID_CREDENTIALS`, `INVALID_OTP` and `INVALID_REFRESH_TOKEN`. Invalid JSON/validation uses 400 `INVALID_REQUEST`; errors do not echo submitted credentials.

The app uses the servlet remote address, not raw `X-Forwarded-For`. If deployed behind a proxy, configure trusted forwarding at the ingress/server and prevent clients from reaching the upstream app directly; otherwise all clients share the proxy's IP limit. Device ID and user agent are bounded metadata, not authentication factors or hard IP/device bindings.

## Tokens and persistence

PostgreSQL stores `auth_sessions` and `refresh_tokens` through JPA entities, Spring Data repositories and JPQL. OTP challenges live only in Redis. V3 and V4 are preserved for Flyway checksum compatibility; V4 adds `is_revoked` to both tables and the refresh-token revocation timestamp, backfilling token-family revocation from existing revoked sessions. V5 moves client metadata from sessions to refresh tokens. No JDBC/native query is introduced for runtime flows.

Each refresh-token row captures the bounded/sanitized `ip_address`, `user_agent` and `device_id` of the request that issued it, including the initial password/OTP login and every rotation. These fields are immutable after issuance; missing headers remain null instead of inheriting earlier values. Normal rotation only consumes the old token and inserts its replacement; it does not update the session. Session identity, absolute expiry and revocation remain session-level state.

Opaque tokens contain 32 random bytes. PostgreSQL stores only SHA-256 refresh-token hashes. Redis stores OTP challenges under `auth:otp:{login}:challenge:<mfaToken>`, containing the user ID, credential version, readable `identifierKey` (for example `identifier:user@example.com`), actual `destination`, plain six-digit `code`, channel, expiry, attempts and state. The original MFA token appears directly in the key and the latest-challenge pointer; the OTP code is stored as text, including leading zeros. `{login}` is a Redis Cluster routing tag that keeps the atomic OTP scripts in one slot; it does not obscure any data. Every challenge and account latest-challenge pointer has the OTP TTL (5 minutes by default); state transitions never extend it. Tokens, codes, passwords and credential hashes are never logged. Application logs use SLF4J fluent `atInfo()/atWarn()/atError()` calls with separate `addKeyValue` fields and a human-readable message. Important auth requests record `ip_address`, `http_method`, `path`, bounded/sanitized `user_agent` and `device_id`. Domain outcomes additionally record user/session IDs when known, authentication method, OTP channel/attempt count, safe failure reason or retry duration. Unknown/expired OTP and refresh credentials, malformed input and dependency failures also record request context. Passwords, OTP values, request bodies, authorization headers and raw access/refresh/MFA tokens are never logged; identifiers use HMAC fingerprints. The servlet remote address is used, ignoring raw forwarded headers. Successful login, session creation and rotation events are emitted after the database commit. Native key/value fields are retained by the existing Logstash JSON encoder. With user approval, only `%kvp` was added to the existing Spring Boot console layout so these fields also appear in the terminal; appenders, levels and destinations are unchanged.

Refresh tokens expire after 7 days of inactivity and rotate on every refresh. A session has an absolute lifetime of 30 days, which rotation never extends. Session validity requires `is_revoked = false`, `revoked_at IS NULL`, and an absolute expiry strictly after the current time. Refresh validity requires `refresh_tokens.is_active = true`, null revocation and consumption timestamps, a future token expiry and an active session. `is_active = false` or a non-null revocation timestamp independently causes rejection. Normal rotation sets the original token's `is_active` to false and records `consumed_at` in the same transaction that inserts an active replacement. A failed transaction rolls back both changes. `consumed_at` remains distinct from `revoked_at`, so reusing a rotated token still revokes its entire family. Revocation on logout, logout-all, refresh reuse/expiry, missing users, account changes, and scheduled cleanup marks both the session and all its refresh tokens in the same transaction, preserving existing revocation timestamps/reasons and consumption history. Expired sessions encountered during refresh are also revoked immediately. Token consumption during normal rotation remains separate from revocation so reuse can still be detected. Each session is a separate token family; concurrent sessions are allowed. Every token replacement belongs to the same family. Refresh looks up the session ID from the refresh token hash, locks the session with JPA `PESSIMISTIC_WRITE`, then reads the refresh token. Logout takes the same lock using the verified access token’s session ID, so any refresh token rotated concurrently is covered by session revocation. Reuse revocation commits even though the response is 401. OTP verification atomically claims its Redis challenge before issuing a session. Only one verifier can claim it. After the database transaction commits, the claim is closed; after a confirmed rollback, only its owner can release it for retry. Unknown outcomes or a crashed verifier leave it claimed until the original TTL expires; a new code can be requested after cooldown. No expiring verification lease can accidentally allow a second issuer while the first transaction is still running. Redis and PostgreSQL do not share a transaction, so this uses an atomic claim with completion callbacks. Atomic Redis failure counters delete challenges on the third incorrect code (configurable through AUTH_OTP_MAX_ATTEMPTS), and an atomic replacement script removes the previous challenge when a new one is issued. OTP state does not require a SQL table or cleanup job.

Access tokens use RS256 with the existing RSA/JWKS setup, `typ=at+jwt`, `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `token_use=access`, `sid`, `credential_version` and `roles`. The decoder pins RS256 and validates issuer, audience, type, timestamps and required claims. The filter derives `ROLE_…` authorities from signed roles. Access token authentication is stateless and validates the JWT locally. Logout, refresh reuse and account changes can revoke the session and refresh tokens. Already-issued access tokens remain valid until their signed expiration, with a configurable lifetime of up to 15 minutes and no clock-skew allowance in Auth. The refresh and logout operations still use PostgreSQL to manage sessions and refresh tokens.

A refresh-token state task runs every minute by default (`AUTH_REFRESH_TOKEN_STATE_INTERVAL`), marking active tokens inactive when consumed, revoked, expired, or attached to an expired/revoked session. It never reactivates tokens, deletes history or fabricates consumption/revocation timestamps. Runtime refresh checks reject expiry immediately and persist deactivation before returning an authentication error; idle expired rows are reconciled on the next task run, so the stored flag can lag wall-clock expiry by a scheduling interval. Changes to an account in User are detected and persisted when refresh revalidates that account. Session archival cleanup remains hourly (first run after one interval, then a fixed delay after each completion). Sessions whose absolute expiry is more than `AUTH_RETENTION` (default 7 days) in the past are revoked, along with every refresh token in their family, without deleting any records. Existing revocation timestamps/reasons and token consumption history are preserved; repeated archival runs preserve existing revocation timestamps. Each archival run also reconciles unusable token activity independently of the retention cutoff. `AUTH_RETENTION` is the delay before archival revocation, not a data deletion period. Session and token history remain stored indefinitely. OTP challenges, latest-challenge pointers, locks and cooldowns expire in Redis through TTL without a scheduler.

Readable Redis key formats:

| Purpose | Key example |
| --- | --- |
| IP request counter | `auth:ip:127.0.0.1` |
| Identifier failure state | `auth:failure:identifier:user@example.com` |
| Account failure state | `auth:failure:account:42` |
| Identifier OTP cooldown | `auth:otp-cooldown:identifier:+989123456789` |
| Account OTP cooldown | `auth:otp-cooldown:account:42` |
| OTP challenge | `auth:otp:{login}:challenge:<mfaToken>` |
| Latest OTP challenge for an account | `auth:otp:{login}:latest:account:42` |

Email and phone values retain the existing normalization; separate `identifier:` and `account:` namespaces avoid collisions. Redis hash fields remain readable via `HGETALL`; Redis hashes are a data structure, not cryptographic hashing.

Deploy the readable-key version across all Auth instances together. Previously hashed Redis keys are not converted or deleted: they expire under their existing TTLs. Old OTP challenges require a fresh code, and request/failure/cooldown state starts anew under the readable keys once at rollout. Existing PostgreSQL sessions and refresh tokens are unaffected. No Redis flush is required.

## Configuration and notification integration

See `.env.example` for every setting. Set Redis connection variables. `AUTH_OTP_SECRET` retains its existing configuration name for compatibility, but is now used only for anonymizing identifiers in audit logs, never for Redis storage or OTP verification. Generate it with `openssl rand -base64 32` and supply the same value to all Auth instances. It must decode to at least 32 bytes. Changing it affects only log fingerprints; it does not invalidate OTPs or reset Redis counters. Supply variables through the IDE/process/deployment; Spring does not automatically load `.env`.

`NotificationService.sendLoginOtp(long userId, OtpChannel channel, String destination, String code)` is intentionally empty. The login flow calls it, but actual email/SMS/in-app delivery requires the user's later integration. No RabbitMQ dependency or configuration was added. Until that integration is implemented, OTP codes are not delivered and OTP login cannot complete through a real notification channel; codes are never exposed in logs/responses as a workaround.

Apply migrations through normal Flyway startup. V4 adds `is_revoked BOOLEAN NOT NULL DEFAULT FALSE` to both `auth_sessions` and `refresh_tokens`, plus the nullable `refresh_tokens.revoked_at` column, without deleting session or token history. Existing session revocations are backfilled into the flags and their complete token families. V5 adds nullable client metadata columns to `refresh_tokens`, copies each session's last-known metadata to its latest token, and drops the three client columns from `auth_sessions`. Older token metadata remains null because its original values were overwritten by earlier rotations and cannot be recovered. If issuance timestamps tie, the unconsumed successor takes precedence. Token/session identities, expiry, consumption and revocation history are preserved. V6 replaces only `refresh_tokens.is_revoked` with `is_active` and backfills activity from the old flag, token consumption/revocation/expiry and session revocation/expiry. It preserves every history row, timestamp and client metadata field; session `is_revoked` remains unchanged. The database default is inactive; Auth explicitly activates newly issued usable tokens. V3–V5 are unchanged. Stop older application instances before applying V5 or V6: they still expect the removed session client columns and/or `refresh_tokens.is_revoked`, so these migrations require a coordinated deployment. Rolling back application code after V6 also requires a schema rollback that maps inactive/consumed/expired state without reactivating any token; an old binary cannot use the V6 schema directly. The existing logging appenders, levels and destinations are preserved; the console layout additionally displays native key/value fields.

## Verification

Unit tests cover token claims/signatures, identifier normalization, OTP hashing and standard security responses. `LoginFlowIntegrationTest` uses real PostgreSQL/JPA transactions and Redis scripts, with the User service and notification boundary replaced locally for tests. It covers concurrent OTP/refresh consumption, committed reuse revocation, logout, lockout, resend, expiry, credential changes, unavailable dependencies and safe error responses.

Set `AUTH_TEST_DATABASE_URL`, `AUTH_TEST_DATABASE_PASSWORD` and `AUTH_TEST_REDIS_PORT` to disposable local instances, then run:

```shell
./mvnw -Dtest=LoginFlowIntegrationTest test
```

The integration test deletes auth state in those disposable stores; it is skipped without `AUTH_TEST_DATABASE_URL`. The existing `AuthApplicationTests` additionally needs the usual database, gRPC and `AUTH_OTP_SECRET` environment settings. Existing advisory-lock tests run when `AUTH_LOCK_TEST_URL` / `AUTH_LOCK_TEST_PASSWORD` point to the disposable database.

Design references: [RFC 9700 refresh-token protection](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14), [OWASP authentication controls](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [Spring Data JPA locking](https://docs.spring.io/spring-data/jpa/reference/jpa/locking.html), [Spring Redis scripting](https://docs.spring.io/spring-data/redis/reference/redis/scripting.html).
