# Auth

Vigo's authentication service handles registration, password and OTP sign-in, expired-password renewal, password changes and resets, and session management.

The [Auth API quick reference](docs/api.md) covers authentication endpoints, request fields, response shapes, frontend actions, and common errors. The [Bruno Auth collection](api-collection/Auth) contains ready-to-run requests.

## Stack and local setup

- Java 21 and Spring Boot serve the API. The service communicates with User over gRPC.
- PostgreSQL stores sessions, refresh token hashes, and settings. Flyway applies database migrations.
- Redis stores OTP challenges, temporary token state, and rate limits. RSA keys sign JWTs.

Start PostgreSQL, Redis, and the User service. Set the environment variables listed in [.env.example](.env.example), including the RSA key paths and `AUTH_OTP_SECRET`, then run `./mvnw spring-boot:run`. Maven needs access to the project's GitHub Packages registry to download the private gRPC contract dependency.

## Email OTP delivery

Auth publishes email OTP commands to the provisioned `notification.commands` topic over `PLAINTEXT`. Set `KAFKA_BOOTSTRAP_SERVERS=kafka:9092` in Compose on `app-network` (the default) or `KAFKA_BOOTSTRAP_SERVERS=127.0.0.1:29092` when running on the Docker host. Configure SMTP and `NOTIFICATION_KAFKA_ENABLED=true` in Notification.

The OTP email uses the first supported language (`fa` or `en`) from `Accept-Language`, with `fa` as the default. Auth reuses a valid UUID from `X-Correlation-ID` or generates a request UUID.

Enable email notifications in the Auth settings to allow email OTP. Passwordless sign-in and password recovery accept requests while delivery runs in the background.

## Running behind Nginx

Spring Boot uses forwarded headers to expose the client IP for audit logs, refresh token records, and rate limits. Keep the Auth port private and allow requests through the trusted Nginx proxy. Once Nginx resolves the client IP from trusted Cloudflare addresses, configure the Auth location to overwrite `X-Forwarded-For` with `$remote_addr` and clear `Forwarded`. Clear or overwrite the other `X-Forwarded-*` headers consumed by Spring as well. For a deployment that accepts direct requests, set `SERVER_FORWARD_HEADERS_STRATEGY=none`.

## Docker build

Pushing a version tag such as `1.1.0` builds and publishes the matching Docker image tag and `latest`.

GitHub Actions uses `MAVEN_USERNAME` (a secret or variable) and `MAVEN_TOKEN` (a secret) to create temporary Maven settings for the Docker build. The token must be a classic GitHub PAT with `read:packages`, and its owner must have access to the contracts package.

For a local Docker build, pass your Maven settings as a build secret. Its server ID must match `github-vigo-contracts` in the POM.

```bash
docker build --secret id=maven_settings,src="$HOME/.m2/settings.xml" -t vigo-auth-service .
```
