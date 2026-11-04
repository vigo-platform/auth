# Auth

Vigo's authentication service handles registration, password and OTP sign-in, expired-password renewal, password changes and resets, and session management.

The [Auth API quick reference](docs/api.md) covers authentication endpoints, request fields, response shapes, frontend actions, and common errors. The [Bruno Auth collection](api-collection/Auth) contains ready-to-run requests.

## Stack and local setup

- Java 21 and Spring Boot serve the API. The service communicates with User over gRPC.
- PostgreSQL stores sessions, refresh token hashes, and settings. Flyway applies database migrations.
- Redis stores OTP challenges, temporary token state, and rate limits. RSA keys sign JWTs.

Start PostgreSQL, Redis, and the User service. Set the environment variables listed in [.env.example](.env.example), including the RSA key paths and `AUTH_OTP_SECRET`, then run `./mvnw spring-boot:run`. Maven needs access to the project's GitHub Packages registry to download the private gRPC contract dependency.

Connect `NotificationService` to a delivery provider to send email and SMS in a running environment.

## Docker build

GitHub Actions uses `MAVEN_USERNAME` (a secret or variable) and `MAVEN_TOKEN` (a secret) to create temporary Maven settings for the Docker build. The token must be a classic GitHub PAT with `read:packages`, and its owner must have access to the contracts package.

For a local Docker build, pass your Maven settings as a build secret. Its server ID must match `github-vigo-contracts` in the POM.

```bash
docker build --secret id=maven_settings,src="$HOME/.m2/settings.xml" -t vigo-auth-service .
```
