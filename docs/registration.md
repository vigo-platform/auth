# Registration API

Registration has three steps: choose one email/phone, verify its code, then choose
a password and create the account. Names are optional. There is no account, session,
or access/refresh token before completion. User remains the owner of account state;
the current User deployment creates active accounts with the supplied contact
already verified. Auth therefore calls `CreateUser` only with a contact proven by
this registration flow, and does not add an activation RPC or a user table.

All paths below are under `/api/v1/auth`, explicitly public in `application.yaml`.
Responses use the existing bilingual `ApiResponse` envelope and `Cache-Control:
no-store`. Credentials go in JSON bodies, never URLs. The API sets no cookies.

## Requests

| Step | Endpoint | JSON body | Successful `data` |
| --- | --- | --- | --- |
| Request code / resend | `POST /register/initiate` | `{"identifier":"new@example.com"}` or `{"identifier":"09111111111"}` | `{"mfaToken":"<43-character token>","channel":"EMAIL","expiresIn":300,"resendAfter":60}` |
| Verify | `POST /register/verify` | `{"mfaToken":"<token>","otp":"012345"}` | `{"registrationToken":"<43-character token>","expiresIn":900}` |
| Complete | `POST /register/complete` | `{"registrationToken":"<proof>","password":"new-password","firstName":"Test","lastName":"User"}` | HTTP 201 with `userId`, `status`, and `tokens` when sign-in is available |

`POST /register` is an alias for **completion**, requiring the same verified proof.
The old email/phone/password body is no longer accepted. Completion cannot change
or add a contact: Auth derives it exclusively from Redis. A second contact can be
added later through a separate contact-verification workflow.

For an eligible account with login enabled, completion creates a session and
returns `data.tokens` with the access token, refresh token, token type, and both
expiration durations. The session uses the existing `/refresh`, `/logout`, and
`/logout-all` endpoints. See the [login response format](login.md#endpoints).
When login is disabled or the new account is ineligible for sign-in, the response
includes `userId` and `status` and omits `tokens`.

`mfa` and `mfa_token` are accepted aliases for `mfaToken`; `registration_token` is
an alias for `registrationToken`. Responses use camelCase. OTPs are six-character
strings so leading zeros are retained. Passwords are never trimmed. The password
minimum is 8 characters and the maximum is 72 UTF-8 bytes, matching login's bcrypt
limit. Names are optional, bounded to 100 characters each.

Emails are stripped/lowercased. Iranian `09…`, `00989…` and `+989…` formats share
one normalized E.164 identity and cooldown. Other phones must be E.164. An email
uses EMAIL; a phone uses SMS. The client need not choose a separate channel.

## Settings and protection

- `registerEnabled` gates **all three stages**, including the `/register` alias,
  before external work. `loginEnabled` controls whether completion also creates
  a session and returns tokens.
- `emailNotificationEnabled` and `smsNotificationEnabled` gate issuance,
  verification, and completion for the selected contact. Disabling a channel or
  registration pauses unexpired challenges/proofs without consuming attempts.
  Re-enabling permits them to continue until their original expiry.
- `defaultOtpChannel` still selects password-login's follow-up OTP. Registration's
  explicit contact determines its channel, so changing the default does not
  reroute registration or invalidate an existing proof. IN_APP cannot verify a guest.
- Settings are rechecked after existence lookup, before sending, before OTP
  verification, after bcrypt, and immediately before calling `CreateUser`. These
  checks use the existing committed settings cache; they do not serialize settings
  changes with in-flight operations. Cross-instance propagation remains as described
  in [auth settings](auth-settings.md).
- Every stage uses the existing IP request limit. Identifier cooldown, progressive
  failure locks, OTP TTL and per-challenge attempts use the same configured policies
  as login through the shared `AuthProtectionService`. Login and registration share
  the normalized identifier cooldown and failure counters, but **never** their challenge/proof keys.
- Existence checks are advisory; User's unique constraints resolve creation races.
  An existing contact returns 409 `ACCOUNT_ALREADY_EXISTS` with a sign-in message.
  This intentionally exposes the same duplicate-account outcome as the old API.
- A resend uses `/register/initiate`, returns a fresh token, and atomically replaces
  the old unverified code. It does not reset failures or bypass the cooldown. Already
  verified proofs retain their own original expiry.

Defaults remain 5 minutes / 6 digits / 3 attempts for a code, 60 seconds between
sends, and 5 failures before the progressive identifier lock. The new
`AUTH_REGISTRATION_TOKEN_TTL` / `auth.registration-token-ttl` defaults to 15 minutes
and controls the time to finish the form after successful verification.

## Redis transitions and retries

`RegistrationRepository` owns the Lua scripts in `redis/registration`. Keys are
readable and namespaced under `auth:registration:{registration}:`; the routing tag
keeps multi-key operations in one Redis Cluster slot. Challenge hashes contain
the canonical identifier, channel, plain code, expiry and failed attempts. Grant
hashes contain only the proven contact, channel, expiry and creation claim state.
Neither passwords nor their hashes are stored in Redis.

OTP comparison, failure counting, challenge consumption and proof creation happen
in one atomic script. Only one concurrent verifier can obtain a proof. Login tokens,
login OTP challenges, registration challenges and registration proofs cannot be
used in each other's endpoints. All temporary state expires through Redis TTLs.

Completion hashes the password, rechecks policy, then atomically claims the proof
before the remote mutation. Only the owner can release or finish that claim.
No short claim lease can permit another mutation while a slow RPC is still running.
A confirmed creation atomically deletes its claimed proof. At most one
completion returns HTTP 201. Repeating a successful request returns 401
`INVALID_REGISTRATION_TOKEN`, including through the `/register` alias. No account
result is cached for replay. If Redis cleanup fails after User already committed,
the successful response is preserved and a warning is audited; the remaining
`CLAIMED` state still cannot create another account. If session creation fails
after the account is created, the completion request returns an error and the
proof stays spent. Offer sign-in if session creation fails or the success response
is lost.

`CreateUser` has no idempotency key. On timeout, transport failure, or an invalid
successful response, the claim stays occupied: the remote account may already
exist. The client must not retry creation blindly. It should offer sign-in or a
fresh registration attempt, whose existence check can detect the account. A
concurrent/incomplete claim returns 409 `REGISTRATION_IN_PROGRESS`. A definitive
`INVALID_ARGUMENT` rejection releases the proof for correcting the form without
extending its TTL. An `ALREADY_EXISTS` rejection returns 409 and does not release
the claim. Losing the verification response requires a new code; a used OTP cannot
produce another proof.

## Delivery boundary

`NotificationService.sendRegistrationOtp(OtpChannel, String destination, String code)`
is the guest delivery integration point. As requested, no mail/SMS provider or
queue is introduced here. Both notification methods are currently placeholders;
real delivery must be connected separately. When the adapter reports a delivery
failure (for example, 503 `OTP_DELIVERY_UNAVAILABLE`), the unsent registration
challenge is deleted. Tests replace this boundary with a test double and exercise
both successful delivery and delivery failure.

## Errors and audit

| HTTP | Code | Client action |
| --- | --- | --- |
| 400 | `INVALID_REQUEST`, `INVALID_IDENTIFIER`, `INVALID_PASSWORD_LENGTH` | Correct the form; a password validation error does not consume the proof. |
| 401 | `INVALID_OTP` | Correct the code, or request a new one if expired/exhausted/used. |
| 401 | `INVALID_REGISTRATION_TOKEN` | The proof is unknown, expired or already consumed. Restart verification if no account was created; otherwise sign in. |
| 409 | `ACCOUNT_ALREADY_EXISTS` | Offer sign-in. |
| 409 | `REGISTRATION_IN_PROGRESS` | Avoid another creation; offer sign-in or fresh verification. |
| 429 | `RATE_LIMITED`, `OTP_COOLDOWN`, `LOGIN_TEMPORARILY_LOCKED` | Wait for `Retry-After` / `data.retryAfterSeconds`. |
| 503 | `REGISTRATION_DISABLED`, `OTP_CHANNEL_DISABLED` | Respect settings and retry when enabled. |
| 503 | `OTP_DELIVERY_UNAVAILABLE`, `AUTH_SERVICE_UNAVAILABLE` | Show a temporary service error. For completion, account creation may have committed. |

Shared request auditing records method/path, source IP, bounded user agent and
device ID. Domain events include `registration_challenge_created`,
`registration_otp_rejected`, `registration_otp_verified`, `registration_creation_failed`, `registration_success`,
and cleanup warnings. Identifiers use the existing HMAC audit fingerprint.
Passwords, hashes, OTP codes, tokens, destinations and request bodies are never
written to application logs. Credential-bearing records redact `toString()`.

## Compatibility and verification

No SQL migration, User contract change, or Redis flush is needed. Existing login
challenges and sessions are unchanged. Clients must switch to the three-step API;
the `/register` body change deliberately removes direct account creation without
proof. Upgrade all Auth instances together so an old instance cannot serve that
old direct endpoint during rollout. The API collection contains all three steps
with separate registration token variables.

The single-use completion rule also rejects `COMPLETED` hashes left by the earlier
result-caching implementation. They expire naturally and do not require a Redis
flush. Deploy the new Auth version on every instance so an old instance cannot
continue replaying cached successful results.

`RegistrationFlowIntegrationTest` exercises the public HTTP routes with Spring
Security, real disposable PostgreSQL/Redis, and User/notification test doubles.
It covers channels/settings between stages, normalized contacts, resend, expiry,
attempt limits, purpose isolation, concurrency, remote failures, rejection of ten
identical completion retries, legacy completed proofs, expiry during creation,
claim ownership and audit redaction. `RegistrationServiceTest` covers
settings changing during password hashing, competing completion claims and cleanup
failures after confirmed creation; `AuthPolicyServiceTest` covers channel
switch combinations independently of the login switch. Use the disposable-store
environment variables in [login verification](login.md#verification), then run:

```shell
./mvnw -Dtest=RegistrationFlowIntegrationTest,RegistrationServiceTest,AuthPolicyServiceTest test
```

`RegistrationUserGrpcIntegrationTest` additionally runs all three registration
stages against a real stateful User mock and disposable Redis, without mocking the
gRPC client. Set `AUTH_TEST_USER_GRPC_PORT` and `AUTH_TEST_REDIS_PORT` to those
isolated services before running it. It verifies active/verified account creation,
contact lookups, preservation of the bcrypt hash and rejection of consumed proofs. This
detects static mocks whose `CreateUser` default rejects every new contact.
