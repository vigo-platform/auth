# Auth

Vigo's authentication service handles registration, password and OTP sign-in, expired-password renewal, password changes and resets, and session management.

The [Auth API quick reference](docs/api.md) covers authentication endpoints, request fields, response shapes, frontend actions, and common errors. The [Bruno Auth collection](api-collection/Auth) contains ready-to-run requests.

## Stack and local setup

- Java 21 and Spring Boot serve the API. The service communicates with User over gRPC.
- PostgreSQL stores sessions, refresh token hashes, and settings. Flyway applies database migrations.
- Redis stores OTP challenges, temporary token state, and rate limits. RSA keys sign JWTs.

Start PostgreSQL, Redis, and the User service. Set the environment variables listed in [.env.example](.env.example), including the RSA key paths and `AUTH_OTP_SECRET`, then run `./mvnw spring-boot:run`. Maven needs access to the project's GitHub Packages registry to download the private gRPC contract dependency.

Connect `NotificationService` to a delivery provider to send email and SMS in a running environment.
