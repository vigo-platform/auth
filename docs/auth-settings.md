# Versioned auth settings

Each settings change is stored as a new row. The row with the highest `version`
is active. `AuthSettingRepository.findFirstByOrderByVersionDescIdDesc()` reads that
row, using descending ID as a deterministic tie-breaker for legacy duplicate versions.

## Startup

`AuthSettingInitializer` calls the transactional `AuthSettingService.initialize()`
before readiness. It loads the latest row unchanged. If no rows exist, it builds
and inserts version 1 using `ApplicationProperties.authDefaults`, populated from
`app.auth-defaults` in `application.yaml`. A database error fails startup instead
of silently reverting to configuration.

## Reading and changing settings

`GET /api/v1/auth/settings` is public so the frontend can read settings before
login. `AuthSettingController` maps the current cached settings to
`AuthSettingResponse` in `data`, wrapped in the shared `ApiResponse<T>` envelope: `success`,
`message`, `message_fa`, `data`, and a UTC ISO-8601 `timestamp`. Successful reads
return HTTP 200 with English/Persian messages and omit `code` entirely (it is
reserved for errors). `data` contains only `loginEnabled`, `registerEnabled`,
`defaultOtpChannel`, `emailNotificationEnabled`, `smsNotificationEnabled`, and
`inAppNotificationEnabled`; internal `id`, `version`, and `updatedAt` remain in
the service DTO and are not exposed to the frontend.
This endpoint reads settings only; it does not create or update revisions.

The immutable Java record `dto.setting.AuthSettingDto` has a Lombok builder and
`toBuilder()`. It is used both for cached reads and edits:

```java
var original = authSettingService.getCurrent();
var edited = original.toBuilder().loginEnabled(false).build();
var saved = authSettingService.update(edited);
```

`getCurrent()` reads only the local cache. `update()` compares the original ID and
version with the current database revision, then builds and inserts a new row with
version + 1. It never modifies the previous row. Stale edits are rejected with an
optimistic locking failure; callers must authorize administration before updating.

A PostgreSQL transaction-level advisory lock serializes initialization and revision
creation across service instances. Its fixed key pair is `(12234, 1)`; do not generate
new keys on each call. The repository returns `void` and directly selects the lock function.
A unique version constraint provides an additional
database guarantee. `version` is a service-managed global revision number, not a
JPA `@Version` field: Hibernate's per-row optimistic version does not count inserts
across different rows.

The cache changes only after a successful commit. Rollback leaves the previous
snapshot intact. Older callbacks cannot replace newer revisions. `reload()` loads
the latest database revision without creating one if none exists. Direct database
changes and changes made by other application instances need explicit reload,
polling, or change notifications; these mechanisms are not implemented here.
History is append-only through this service; deleting or rewriting revisions is not
supported. Restoring old settings means inserting a new revision with the old values.

## Logging

The service uses plain `log.info(...)` messages for creation from defaults, startup
loading, reload, and new revisions, including the settings ID and version. Messages
are written only after commit and successful cache application. Normal reads, failed
operations, and skipped older snapshots do not produce success messages.

The console retains Spring Boot's default text format. Vector still encodes these
messages as JSON through the existing Logback configuration.

## Schema prerequisites

No migrations were generated or run. Before running the application:

- Keep generated identity IDs; there is no fixed-ID or singleton constraint.
- If `CHECK (id = 1)` was installed after the earlier design, remove it through a migration.
- Add `updated_at TIMESTAMP WITH TIME ZONE NOT NULL` and backfill existing rows.
  The current V2 adds `TIMESTAMP WITHOUT TIME ZONE`; align the column with the
  entity's `Instant` mapping. If rows already exist, populate their timestamps
  before applying `NOT NULL` (the current V2 does not backfill them).
- Ensure historical versions are distinct, then add `UNIQUE (version)` as declared
  by the entity. Legacy per-row `@Version` values may be duplicated and need
  renumbering in the intended historical order before adding this constraint.
- If V1 was already applied, use a new migration version. Hibernate validation does
  not install constraints or perform these data conversions.

Hibernate populates `updatedAt` on insert and Hibernate-managed updates. The service
only inserts revisions, so this is the time each revision was saved. The timestamp
is not used to select the current revision or trigger cache reload.

## Verification

`AuthSettingServiceTest` exercises real Spring transaction interception and commit/
rollback handling with mocked JDBC and repository interfaces, without a database or
Flyway. It covers startup defaults, preservation of history, increasing versions,
stale edits, cache visibility, reload, and failures. PostgreSQL query execution and
schema constraints still need verification against a disposable PostgreSQL database.

`AuthSettingRepositoryLockTest` additionally verifies the real repository query on
PostgreSQL, including mutual exclusion and release after both commit and rollback.
It runs only when `AUTH_LOCK_TEST_URL` and `AUTH_LOCK_TEST_PASSWORD` point to a
disposable PostgreSQL database. It creates no tables and runs no migrations.
