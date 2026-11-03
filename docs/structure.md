# Project structure

This service uses a small layered package structure under `ir.vigoapp.auth`:

| Package | Responsibility |
| --- | --- |
| `bootstrap` | Startup initialization, including the first auth settings revision. |
| `client.user` | The User service gRPC adapter, its private commands/models and errors. |
| `config` | Spring configuration and validated application properties. |
| `controller` | Separate login/registration controllers, settings/JWKS endpoints, and shared safe request auditing/cache policy in `AuthRequestAdvice`. |
| `dto` | Data transferred between layers. Shared request metadata is `ClientInfo`; login, registration, token and settings DTOs have their own subpackages. |
| `entity` | JPA entities mapped to PostgreSQL tables. |
| `exception` | Application errors and their HTTP translation. |
| `model` | Login state (`OtpChallenge`) and shared `OtpChannel`; guest challenges and verified proofs live in `model.registration`. |
| `repository` | JPA and login Redis access; `repository.registration.RegistrationRepository` owns guest challenge/proof persistence. |
| `scheduling` | Scheduled auth state cleanup. |
| `security` | Token generation, JWT handling, security handlers and login policies in `security.login`. |
| `service` | Login, registration, session, settings, runtime auth policy, shared authentication protection (`AuthProtectionService`) and notification workflows. |

Keep service packages for workflows; place request data in DTOs, stored internal
state in models, and storage operations in repositories. The User client's models
remain beside that adapter because they represent its external contract. Test
packages follow the classes they exercise; the complete login flow integration
tests stay under `service`, with shared external test doubles in `support`.
Registration's atomic storage scripts are grouped under `resources/redis/registration`;
they use a separate namespace from the login scripts.

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

This structure needs no database migration. The staged registration API creates
accounts through `/register/complete`.
See [registration compatibility](registration.md#compatibility-and-verification).
