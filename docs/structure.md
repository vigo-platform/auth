# Project structure

This service uses a small layered package structure under `ir.vigoapp.auth`:

| Package | Responsibility |
| --- | --- |
| `bootstrap` | Startup initialization, including the first auth settings revision. |
| `client.user` | The User service gRPC adapter, its private commands/models and errors. |
| `config` | Spring configuration and validated application properties. |
| `controller` | HTTP endpoints and request/response handling. |
| `dto` | Data transferred between layers. Shared request metadata is `ClientInfo`; login, token and settings DTOs have their own subpackages. |
| `entity` | JPA entities mapped to PostgreSQL tables. |
| `exception` | Application errors and their HTTP translation. |
| `model` | Internal auth state and shared value types: `OtpChallenge` and `OtpChannel`. |
| `repository` | Persistence access, including the Redis-backed `OtpChallengeRepository`. |
| `scheduling` | Scheduled auth state cleanup. |
| `security` | Token generation, JWT handling, security handlers and login policies in `security.login`. |
| `service` | Login, registration, session, settings, runtime auth policy, login protection and notification workflows. |

Keep service packages for workflows; place request data in DTOs, stored internal
state in models, and storage operations in repositories. The User client's models
remain beside that adapter because they represent its external contract. Test
packages follow the classes they exercise; the complete login flow integration
test stays under `service`.

## Record construction

All production records expose Lombok `@Builder`. Prefer named builder fields when
creating records with several values, especially adjacent booleans and durations.
`AuthSettingDto` and `UserAccount` also expose `toBuilder()` for copying snapshots.
Use the existing named factories, such as `ClientInfo.from(...)`,
`LoginResponse.authenticated(...)` and `AuthSettingResponse.from(...)`, when they
express an operation or mapping.

Builders call the record's canonical constructor, so `ClientInfo` still sanitizes
and bounds metadata and `UserAccount` still copies its roles into an immutable
list. HTTP requests continue to use record deserialization and Jakarta validation.
Sensitive records keep their redacted `toString()` implementations.

Package moves do not change HTTP paths, JSON fields, PostgreSQL schemas, Redis
keys, or Redis hash fields. No database migration is needed for this structure.
