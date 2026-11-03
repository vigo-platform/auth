# Password lifecycle design

Auth is a Java 21 Spring Boot service. Keep the current REST envelope, User gRPC adapter, Redis challenge pattern and PostgreSQL session storage. User owns the password hash, credential version and expiration. Auth owns proof of identity, password validation and session issuance.

## Expired password during login

Split account eligibility into eligibility to prove identity (active status) and eligibility to receive a session (active status and valid credentials). Keep verified-destination, channel, lockout and identity checks. Keep the strict predicate in both session creation and refresh.

| Login path | Final proof before checking expiry |
| --- | --- |
| Password only | Correct password |
| Password with account 2FA or global password OTP | Correct password, then correct OTP through the existing challenge |
| Passwordless email/SMS | Correct OTP and a fresh check that account 2FA is off |

The OTP initiation response stays generic. Incorrect passwords and codes retain the current errors. OTP verification re-fetches the account and checks status, version, delivery destination and current factor policy. For an active expired account, return HTTP 200 with `data.step = PASSWORD_CHANGE_REQUIRED` and `data.passwordChange = {passwordChangeToken, expiresIn}`. Return the existing `SUCCESS` and `OTP_REQUIRED` shapes for the other branches. Switch on the step in LoginController and the frontend. The expiration branch creates no session or token pair and records proof completion separately from successful login.

`POST /password/expired/complete` accepts `{passwordChangeToken, newPassword}`. After a confirmed password update, fetch the account again and require a matching ID, the exact version returned by the mutation, active status and cleared expiry. Before issuing the pair, recheck current login policy and that the saved factor proof still satisfies it, including the verified OTP destination if applicable. Return the usual `SUCCESS` with a fresh pair. If the password update is confirmed but a new session cannot be issued, return `PASSWORD_UPDATED_LOGIN_REQUIRED` and let the user sign in normally.

## Change a password from an active session

1. `POST /password/change/initiate` takes a bearer access token and `{currentPassword}`. Derive the user ID and session ID from the verified JWT. Check the PostgreSQL session for ownership, revocation, expiry and matching credential version. Compare the current password against User's current hash and apply existing password attempt protections.
2. If account 2FA or global password OTP applies, return an operation-specific OTP challenge. `POST /password/change/verify` takes the same session's bearer token and `{mfaToken, otp}`. Recheck the session, account, credential version and verified destination and exchange the OTP for a change grant. Otherwise issue the grant at initiation.
3. `POST /password/change/complete` takes the same session's bearer token and `{passwordChangeToken, newPassword}`. Recheck session, identity, version and factor policy before calling User. Return `PASSWORD_UPDATED_LOGIN_REQUIRED` after success and discard the old token pair on the client.

## Reset a forgotten password

1. `POST /password/reset/initiate` takes `{identifier}`. Normalize it like login and select only pre-verified recovery contacts belonging to that account. Return the same HTTP status, response fields and message for real and decoy requests, and send notifications outside the response path so delivery timing and errors do not disclose eligibility. Apply IP, normalized-identifier and account limits. Keep recovery attempt counters separate from login lockouts.
2. `POST /password/reset/verify` accepts `{mfaToken, otp}`. For an account with 2FA, require a second code on the other verified channel (email plus SMS) before issuing a grant. The second `OTP_REQUIRED` response includes a new challenge and token. A successful final proof returns `PASSWORD_RESET_REQUIRED` with `data.passwordReset = {passwordResetToken, expiresIn}`. Enrolled accounts without two available verified channels need assisted recovery outside this API. Check the code before calling User, then re-fetch account, version and verified destinations before exchanging the final proof for a reset grant. Apply the current delivery-channel switches. Recovery leaves the account's 2FA settings intact.
3. `POST /password/reset/complete` accepts `{passwordResetToken, newPassword}`. Recheck the account and recovery proof, then update the password. Return `PASSWORD_UPDATED_LOGIN_REQUIRED` and send a password-change notification without credential material. The next login follows the normal factor policy.

All routes are under `/api/v1/auth`. Only the logged-in change routes require a bearer token. Every route uses the existing bilingual `ApiResponse` and `Cache-Control: no-store`.

## Shared password and grant rules

- Extract the registration password policy and apply it to all three completion routes before claiming the grant. Preserve the current nonblank minimum of eight Java string units and maximum of 72 UTF-8 bytes for BCrypt. Preserve the original string, including whitespace. Check the candidate against the current hash and reject reuse with a password-field error. Hash once with the existing encoder and send only the encoded hash to User. Validation errors allow correction until the grant expires.
- Use 32 random bytes and a five-minute default TTL for each grant. Set `AUTH_PASSWORD_GRANT_TTL` to a duration between 30 seconds and 15 minutes. Store only the token hash in Redis, with purpose, user ID, credential version, expiry, proven factors, verified destinations where applicable and the initiating session ID for logged-in changes. Use separate purposes for expired login, logged-in change and recovery. Bind OTPs to their operation too. Exchange the final OTP for its grant atomically in Redis to prevent duplicate grants or losing a consumed OTP if the write fails.
- Atomically claim an open, unexpired grant before the remote mutation. Mark it spent on confirmed success or a credential-version conflict. A failure proven to occur before dispatch may reopen the claim. On timeout, transport failure or an invalid success response, retain the claim until expiration and return an outcome-unknown error. Ask the user to try signing in with the chosen password or start a fresh flow. A fresh version alone cannot prove which request performed the update.
- Return a generic 401 for invalid, expired, wrong-purpose or spent grants, 409 for an active claim or stale credentials, 429 for throttling and 503 when a required dependency is unavailable. Avoid logging passwords, hashes, OTPs, raw tokens or delivery addresses.

## User contract and session consistency

Contract 3.1.0 already provides `ChangeUserPassword`. Call `UserGrpcClient.changeUserPassword` with `userId`, `newPasswordHash` and the grant's `expectedCredentialVersion`. User must update the hash, password expiration state and credential version atomically. The RPC rejects a mismatched version with `ABORTED` and returns the new version on success. Verify the User deployment also rejects a non-active account at mutation time. User-side status, factor and recovery-contact changes that invalidate previously proved identity must be serialized with the credential update or advance the version checked by the RPC. Auth-side reads alone leave a race. The contract has no idempotency key.

After confirmed mutation, use the existing version-filtered revocation queries in one PostgreSQL transaction for sessions and refresh tokens with older credential versions. This preserves a newer session created concurrently. A database failure cannot roll back User's update. The existing refresh-time version check remains the fallback, and the expired-login route requires a fresh login if session issuance fails. Already issued access JWTs stay valid until expiry (at most 15 minutes with current settings). Sensitive logged-in change routes explicitly check live session state.

## Rollout and verification

1. Verify User's mutation behavior against the deployed server and connect the notification transport. The current Auth notification methods are delivery boundaries with empty implementations.
2. Release frontend support for the additional login step before deploying Auth across instances. No Auth SQL schema change is needed. If rolling back, deploy the preceding Auth version. Short-lived Redis entries expire naturally.
3. Cover each final login factor, eligible and ineligible statuses, wrong OTP/password, expiry and token replay, cross-purpose use, password reuse, multibyte BCrypt bounds, revoked sessions, changed version/destination/2FA, real and decoy recovery, and preservation of the strict refresh gate. Run concurrent OTP and grant redemption and simulate mutation timeout, Redis failure and session commit failure. Verify no login tokens are returned before the confirmed update and fresh account checks.
