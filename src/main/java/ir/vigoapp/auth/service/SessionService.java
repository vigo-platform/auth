package ir.vigoapp.auth.service;

import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.token.TokenResponse;
import ir.vigoapp.auth.entity.AuthSession;
import ir.vigoapp.auth.entity.RefreshToken;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.repository.AuthSessionRepository;
import ir.vigoapp.auth.repository.RefreshTokenRepository;
import ir.vigoapp.auth.security.SecureTokens;
import ir.vigoapp.auth.security.jwt.AccessTokenService;
import ir.vigoapp.auth.security.login.AccountEligibility;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
@Slf4j
@RequiredArgsConstructor
public class SessionService {
    private final AuthSessionRepository sessions;
    private final RefreshTokenRepository refreshTokens;
    private final UserGrpcClient users;
    private final AccessTokenService accessTokens;
    private final SecureTokens tokens;
    private final AuthProperties properties;
    private final LoginProtectionService protection;
    private final Clock clock;

    @Transactional
    public TokenResponse create(UserAccount user, ClientInfo client) {
        // TODO(credentials-expiry): Implement after registration/change_password. This is the final
        // gate shared by correct password-only login, password + verified 2FA, and verified
        // passwordless OTP. If credentialsExpired is true, continue to a required new-password step
        // instead of rejecting login here. Only a successful password change in User should clear
        // credentialsExpired; then revalidate the account and issue the normal session/tokens.
        // Do not clear expiry merely because authentication succeeded or issue tokens before the
        // password change. Coordinate with AccountEligibility to remove its early expiry checks.
        if (!AccountEligibility.canLogin(user)) throw AuthException.invalidCredentials();
        Instant now = clock.instant();
        var session = sessions.save(new AuthSession(user, now, now.plus(properties.getSessionTtl())));
        var response = issuePair(user, session, now, client);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                log.atInfo().addKeyValue("event", "session_created").addKeyValue("result", "SUCCESS")
                        .addKeyValue("user_id", user.userId()).addKeyValue("session_id", session.getId())
                        .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                        .addKeyValue("device_id", client.deviceId()).log("Authentication session created.");
            }
        });
        return response;
    }

    // Security revocations must commit even when the endpoint returns an authentication error.
    @Transactional(noRollbackFor = AuthException.class)
    public TokenResponse refresh(String rawToken, ClientInfo client) {
        protection.checkIp(client);
        String hash = tokens.hash(rawToken);
        UUID sessionId = refreshTokens.findSessionIdByTokenHash(hash).orElseThrow(AuthException::invalidRefreshToken);
        var session = sessions.findLockedById(sessionId).orElseThrow(AuthException::invalidRefreshToken);
        var token = refreshTokens.findByTokenHash(hash).orElseThrow(AuthException::invalidRefreshToken);
        Instant now = clock.instant();
        if (!session.isActive(now)) {
            revokeSession(session, now, session.getExpiresAt().isAfter(now) ? "SESSION_REVOKED" : "SESSION_EXPIRED");
            log.atWarn().addKeyValue("event", "refresh_rejected").addKeyValue("result", "REJECTED")
                    .addKeyValue("reason", "session_inactive").addKeyValue("revoked_reason", session.getRevokedReason())
                    .addKeyValue("user_id", session.getUserId()).addKeyValue("session_id", sessionId)
                    .addKeyValue("ip_address", client.ipAddress()).log("Refresh requested for an inactive session.");
            throw AuthException.invalidRefreshToken();
        }
        if (token.getConsumedAt() != null) {
            revokeSession(session, now, "REFRESH_REUSE");
            log.atWarn().addKeyValue("event", "refresh_reuse_detected").addKeyValue("result", "REJECTED")
                    .addKeyValue("user_id", session.getUserId()).addKeyValue("session_id", sessionId)
                    .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                    .addKeyValue("device_id", client.deviceId()).log("Consumed refresh token reused; session revocation requested.");
            throw AuthException.invalidRefreshToken();
        }
        if (!token.getExpiresAt().isAfter(now)) {
            revokeSession(session, now, "REFRESH_EXPIRED");
            log.atWarn().addKeyValue("event", "refresh_rejected").addKeyValue("result", "REJECTED")
                    .addKeyValue("reason", "refresh_expired").addKeyValue("user_id", session.getUserId())
                    .addKeyValue("session_id", sessionId).addKeyValue("ip_address", client.ipAddress())
                    .log("Expired refresh token rejected.");
            throw AuthException.invalidRefreshToken();
        }
        if (!token.isActive() || token.getRevokedAt() != null) {
            token.revoke(now);
            log.atWarn().addKeyValue("event", "refresh_rejected").addKeyValue("result", "REJECTED")
                    .addKeyValue("reason", "refresh_inactive").addKeyValue("user_id", session.getUserId())
                    .addKeyValue("session_id", sessionId).addKeyValue("ip_address", client.ipAddress())
                    .log("Inactive refresh token rejected.");
            throw AuthException.invalidRefreshToken();
        }

        UserAccount user;
        try {
            user = users.getUserById(session.getUserId());
        } catch (UserClientException exception) {
            if (exception.getCode() != UserClientException.Code.NOT_FOUND) throw exception;
            revokeSession(session, now, "USER_NOT_FOUND");
            throw AuthException.invalidRefreshToken();
        }
        if (user.userId() != session.getUserId()) {
            throw new UserClientException(UserClientException.Code.INVALID_RESPONSE, "GetUserById");
        }
        boolean accountIneligible = !AccountEligibility.canLogin(user);
        if (accountIneligible || user.credentialVersion() != session.getCredentialVersion()) {
            if (accountIneligible) {
                sessions.revokeAllByUserId(user.userId(), now, "USER_STATE_CHANGED");
                refreshTokens.revokeAllByUserId(user.userId(), now);
            } else {
                // Preserve current credentials and any newer login committed after the User snapshot.
                sessions.revokeOlderCredentialsByUserId(user.userId(), user.credentialVersion(), now, "USER_STATE_CHANGED");
                refreshTokens.revokeOlderCredentialsByUserId(user.userId(), user.credentialVersion(), now);
            }
            log.atWarn().addKeyValue("event", "refresh_rejected").addKeyValue("result", "REJECTED")
                    .addKeyValue("user_id", user.userId()).addKeyValue("session_id", sessionId)
                    .addKeyValue("reason", accountIneligible ? "user_state_changed" : "credential_version_changed")
                    .addKeyValue("ip_address", client.ipAddress())
                    .log("Account state or credentials changed; affected user sessions require revocation.");
            throw AuthException.invalidRefreshToken();
        }

        // Recheck time after the remote call, before consuming or issuing anything.
        now = clock.instant();
        if (!token.isUsable(now)) {
            revokeSession(session, now, session.getExpiresAt().isAfter(now) ? "REFRESH_EXPIRED" : "SESSION_EXPIRED");
            throw AuthException.invalidRefreshToken();
        }
        token.consume(now);
        var response = issuePair(user, session, now, client);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                log.atInfo().addKeyValue("event", "refresh_rotated").addKeyValue("result", "SUCCESS")
                        .addKeyValue("user_id", user.userId()).addKeyValue("session_id", sessionId)
                        .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                        .addKeyValue("device_id", client.deviceId()).log("Refresh token rotated successfully.");
            }
        });
        return response;
    }

    @Transactional
    public void logout(String rawToken, ClientInfo client) {
        // A consumed ancestor still identifies its session, so logout also wins a race against rotation.
        refreshTokens.findSessionIdByTokenHash(tokens.hash(rawToken)).flatMap(sessions::findLockedById).ifPresentOrElse(session -> {
            revokeSession(session, clock.instant(), "LOGOUT");
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    log.atInfo().addKeyValue("event", "session_logged_out").addKeyValue("result", "SUCCESS")
                            .addKeyValue("user_id", session.getUserId()).addKeyValue("session_id", session.getId())
                            .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                            .addKeyValue("device_id", client.deviceId()).log("Session logged out.");
                }
            });
        }, () -> log.atInfo().addKeyValue("event", "logout_no_session").addKeyValue("result", "NO_SESSION")
                .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                .addKeyValue("device_id", client.deviceId()).log("Logout completed without a matching session."));
    }

    @Transactional
    public void logoutAll(long userId, ClientInfo client) {
        Instant now = clock.instant();
        int count = sessions.revokeAllByUserId(userId, now, "LOGOUT_ALL");
        refreshTokens.revokeAllByUserId(userId, now);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                log.atInfo().addKeyValue("event", "all_sessions_logged_out").addKeyValue("result", "SUCCESS")
                        .addKeyValue("user_id", userId).addKeyValue("revoked_count", count)
                        .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                        .addKeyValue("device_id", client.deviceId()).log("All user sessions logged out.");
            }
        });
    }

    @Transactional(readOnly = true)
    public boolean isAccessSessionActive(Jwt jwt) {
        try {
            var version = (Number) jwt.getClaim("credential_version");
            return sessions.existsByIdAndUserIdAndCredentialVersionAndRevokedFalseAndRevokedAtIsNullAndExpiresAtAfter(
                    UUID.fromString(jwt.getClaimAsString("sid")), Long.parseLong(jwt.getSubject()),
                    version.longValue(), clock.instant());
        } catch (IllegalArgumentException | NullPointerException | ClassCastException exception) {
            return false;
        }
    }

    private void revokeSession(AuthSession session, Instant now, String reason) {
        session.revoke(now, reason);
        refreshTokens.revokeAllBySessionId(session.getId(), now);
    }

    private TokenResponse issuePair(UserAccount user, AuthSession session, Instant now, ClientInfo client) {
        String refreshToken = tokens.randomToken();
        Instant refreshExpires = now.plus(properties.getRefreshTokenTtl());
        if (refreshExpires.isAfter(session.getExpiresAt())) refreshExpires = session.getExpiresAt();
        refreshTokens.save(new RefreshToken(session, tokens.hash(refreshToken), now, refreshExpires, client));
        var accessToken = accessTokens.issue(user, session, now);
        return TokenResponse.builder()
                .tokenType("Bearer")
                .accessToken(accessToken.getTokenValue())
                .accessExpiresIn(Duration.between(now, accessToken.getExpiresAt()).toSeconds())
                .refreshToken(refreshToken)
                .refreshExpiresIn(Duration.between(now, refreshExpires).toSeconds())
                .build();
    }
}
