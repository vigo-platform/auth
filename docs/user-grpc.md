# Auth → User gRPC integration

Inject `ir.vigoapp.auth.client.user.UserGrpcClient` by constructor. It provides all eight RPCs from `users-grpc-contract:3.0.0`. Request/response records have separate files under `client.user.model`; errors use `client.user.exception.UserClientException`. All integration classes live under `client.user`.

## Configuration

Environment → `application.yaml` → `ApplicationProperties.userGrpc` → channel, stub and client.

Only three settings are needed:

| YAML key | Environment variable | Meaning |
| --- | --- | --- |
| `app.user-grpc.host` | `USER_GRPC_HOST` | Required hostname/IP without a scheme or path |
| `app.user-grpc.port` | `USER_GRPC_PORT` | Required gRPC port, 1–65535 |
| `app.user-grpc.timeout-ms` | `USER_GRPC_TIMEOUT_MS` | Positive per-call deadline; defaults to 3000 ms |

```dotenv
USER_GRPC_HOST=127.0.0.1
USER_GRPC_PORT=50051
USER_GRPC_TIMEOUT_MS=3000
```

The client uses plaintext gRPC without TLS, certificates or service tokens, as requested for the current same-server deployment. User must also accept plaintext connections without service authentication on this endpoint. When services run directly on the host, use a loopback address. Containers use their internal service hostname and container gRPC port.

All settings are bound and validated inside `ApplicationProperties`; JWT retains its separate properties class. `.env.example` documents the variables. Spring does not automatically import a `.env` file: supply variables through the IDE, process environment or deployment configuration.

A channel and blocking stub are reused. Each RPC gets a fresh deadline. Spring closes the channel and cancels outstanding calls when the application stops. Startup constructs the channel lazily; reachability is checked when a call executes.

## Application behavior

The client supports login lookup by email/phone/ID, account lookup by ID, email/phone existence checks, account creation and password changes. Missing identifiers map to `null`. Account status, verification flags, credential version and credential expiration are preserved; unknown statuses map to `UNKNOWN` and must never grant access.

Auth owns password verification, account eligibility, JWT issuance, authorization of password changes/resets, recovery challenges and password hashing. Deploy User's expiration calculation before relying on `credentialsExpired`: proto3 cannot distinguish an omitted boolean from `false`.

Credential-bearing models redact `toString()`, but must never be returned from controllers or serialized into logs/traces. The adapter installs no payload logging.

Remote errors become `UserClientException` with a safe operation name and code. For example, NOT_FOUND stays NOT_FOUND, ABORTED becomes CONFLICT, DEADLINE_EXCEEDED becomes TIMEOUT, and malformed successful responses become INVALID_RESPONSE. Remote descriptions, trailers and original exceptions are omitted to avoid leaking credentials. Local invalid inputs raise `IllegalArgumentException`.

Automatic retries and resolver-provided service configs are disabled. Contract 3.0.0 removes `idempotency_key` from both mutation requests, so `CreateUserCommand` and `ChangePasswordCommand` do not accept an idempotency key. A mutation timeout may mean the operation already committed; callers must reconcile the outcome before deciding whether to issue another mutation. User owns atomic credential version checks and database uniqueness. Existence checks are advisory.

## Verification

```shell
./mvnw -Dtest=UserGrpcConfigTest,UserGrpcClientTest,SecurityHandlersTest test
```

Tests cover property binding and validation, channel cleanup, all eight RPCs over the configured plaintext channel, deadline renewal, safe errors and mutation payload preservation. Loopback sockets and synthetic data are used.
