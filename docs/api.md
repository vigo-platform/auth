# Auth API quick reference

Auth handles sign-in, registration, password management, and sessions. It reads account details and updates passwords through the User service. It issues JWT access tokens and refresh tokens.

## Response format

Paths in the tables are relative to `/api/v1/auth` unless shown in full. Send request bodies as JSON. Rows marked **Bearer** require the `Authorization: Bearer <accessToken>` header.

API responses contain `success`, `message`, `messageFa`, `data`, and `timestamp`. Errors set `success` to `false` and include a `code`. Successful requests return `200`, except registration completion, which returns `201`.

| `data.step` | Response payload | Frontend action |
|---|---|---|
| `SUCCESS` | `data.tokens` | Store both tokens and continue into the app. |
| `OTP_REQUIRED` | `data.challenge` with `mfaToken`, `channel`, `expiresIn`, and `resendAfter` | Prompt for the code and submit it to the current flow's verification endpoint. |
| `PASSWORD_CHANGE_REQUIRED` | `data.passwordChange` with `passwordChangeToken` and `expiresIn` | Submit a new password to the completion endpoint for expired-password sign-in or signed-in password change. |
| `PASSWORD_RESET_REQUIRED` | `data.passwordReset` with `passwordResetToken` and `expiresIn` | Submit a new password to the reset completion endpoint. |
| `PASSWORD_UPDATED_LOGIN_REQUIRED` | `step` only | The password has been updated. Send the user to sign-in. |

A token pair includes `tokenType` (always `Bearer`), `accessToken`, `accessExpiresIn`, `refreshToken`, and `refreshExpiresIn`. Expiration and wait times are in seconds. Send `otp` as a six-digit string to preserve leading zeros. A new password must be at least 8 characters and at most 72 UTF-8 bytes. When updating a password, choose one different from the current password.

## Sign-in and expired passwords

| Request | Body fields | Success response and next action |
|---|---|---|
| `POST /login-password` | `identifier` (email or phone), `password` | `SUCCESS` when sign-in is complete, `OTP_REQUIRED` when a code is needed, or `PASSWORD_CHANGE_REQUIRED` when verification is complete and the password has expired. |
| `POST /login-otp-email` | `email` | `OTP_REQUIRED` → `/verify`. The generic response leaves delivery unconfirmed. |
| `POST /login-otp-phone` | `phone` | `OTP_REQUIRED` → `/verify`. The generic response leaves delivery unconfirmed. |
| `POST /verify` | `mfaToken`, `otp` | `SUCCESS`, or `PASSWORD_CHANGE_REQUIRED` if the password has expired. |
| `POST /password/expired/complete` | `passwordChangeToken` from sign-in, `newPassword` | `SUCCESS` with both tokens. If the password was updated but a new session could not be created, returns `PASSWORD_UPDATED_LOGIN_REQUIRED`. |

## Signed-in password change and forgotten-password reset

| Request | Body fields | Success response and next action |
|---|---|---|
| `POST /password/change/initiate` **Bearer** | `currentPassword` | `OTP_REQUIRED` → `/password/change/verify`, or `PASSWORD_CHANGE_REQUIRED` → `/password/change/complete`. |
| `POST /password/change/verify` **Bearer** | `mfaToken`, `otp` | `PASSWORD_CHANGE_REQUIRED` → `/password/change/complete`. |
| `POST /password/change/complete` **Bearer** | `passwordChangeToken` from the signed-in change flow, `newPassword` | `PASSWORD_UPDATED_LOGIN_REQUIRED`. Use the same session for all three signed-in change requests. |
| `POST /password/reset/initiate` | `identifier` (email or phone) | `OTP_REQUIRED` → `/password/reset/verify`. The generic response leaves delivery unconfirmed. |
| `POST /password/reset/verify` | `mfaToken`, `otp` | `PASSWORD_RESET_REQUIRED` → `/password/reset/complete`. For accounts with 2FA, the first valid code returns `OTP_REQUIRED` with a new challenge on the other channel. Submit the second code and the new `mfaToken` to this same endpoint. |
| `POST /password/reset/complete` | `passwordResetToken`, `newPassword` | `PASSWORD_UPDATED_LOGIN_REQUIRED`. |

Each flow has its own tokens. A `passwordChangeToken` issued during sign-in is valid only at `/password/expired/complete`.

## Registration, sessions, and settings

| Request | Body fields | Success response |
|---|---|---|
| `POST /register/initiate` | `identifier` (email or phone) | `data` contains `mfaToken`, `channel`, `expiresIn`, and `resendAfter`. |
| `POST /register/verify` | `mfaToken`, `otp` | `data` contains `registrationToken` and `expiresIn`. |
| `POST /register/complete` | `registrationToken`, `password`, optional `firstName` and `lastName` | `201` with `data.userId` and `data.status`. Includes `data.tokens` when the account is active, the password is current, and sign-in is enabled. |
| `POST /refresh` | `refreshToken` | A fresh token pair directly in `data`. Replace both tokens. Reusing a consumed refresh token revokes the session. |
| `POST /logout` **Bearer** | None | Revokes the current session and returns `data` as `null`. |
| `POST /logout-all` **Bearer** | None | Revokes all account sessions and returns `data` as `null`. |
| `GET /settings` | None | `data` contains `loginEnabled`, `registerEnabled`, `defaultOtpChannel`, `emailNotificationEnabled`, `smsNotificationEnabled`, and `inAppNotificationEnabled`. |

These endpoints omit `data.step`. Clear both tokens from the client after logout. Session revocation blocks refresh, and issued access tokens can remain valid until they expire. Channel values are `EMAIL`, `SMS`, and `IN_APP`. Registration and password reset use email or SMS.

## Endpoints outside the API prefix

| Full path | Response |
|---|---|
| `GET /.well-known/jwks.json` | Standard JWKS JSON with public `keys` for JWT verification. |

## Common errors

| HTTP status | Example codes and handling |
|---|---|
| `400` | `INVALID_REQUEST`, `INVALID_PASSWORD_LENGTH`, or `PASSWORD_REUSED`. Field validation errors appear in `data.errors` when available. |
| `401` | `INVALID_CREDENTIALS`, `INVALID_OTP`, `INVALID_PASSWORD_TOKEN`, `INVALID_REGISTRATION_TOKEN`, or `INVALID_REFRESH_TOKEN`. Restart the relevant flow when its temporary token expires. Send the user to sign-in if refresh is rejected. |
| `403` | `ACCESS_DENIED`. The request lacks permission. |
| `409` | `ACCOUNT_ALREADY_EXISTS`, `REGISTRATION_IN_PROGRESS`, or `PASSWORD_UPDATE_CONFLICT`. |
| `429` | Request or attempt limit reached. Read the wait time from `Retry-After` or `data.retryAfterSeconds`. |
| `503` | `LOGIN_DISABLED`, `REGISTRATION_DISABLED`, `OTP_CHANNEL_DISABLED`, or `AUTH_SERVICE_UNAVAILABLE`. For `PASSWORD_UPDATE_OUTCOME_UNKNOWN`, the user can try signing in with the new password or restart the flow. |
