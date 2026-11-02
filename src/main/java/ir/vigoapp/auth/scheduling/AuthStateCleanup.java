package ir.vigoapp.auth.scheduling;

import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.repository.AuthSessionRepository;
import ir.vigoapp.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;

@Component
@Slf4j
@RequiredArgsConstructor
public class AuthStateCleanup {
    private final AuthSessionRepository sessions;
    private final RefreshTokenRepository refreshTokens;
    private final AuthProperties properties;
    private final Clock clock;

    @Scheduled(fixedDelayString = "${auth.refresh-token-state-interval:PT1M}",
            initialDelayString = "${auth.refresh-token-state-interval:PT1M}")
    @Transactional
    public void deactivateUnusableRefreshTokens() {
        int count = refreshTokens.deactivateUnusable(clock.instant());
        if (count > 0) {
            log.atInfo().addKeyValue("event", "refresh_tokens_deactivated").addKeyValue("refresh_tokens", count)
                    .log("Unusable refresh tokens marked inactive; history retained.");
        }
    }

    @Scheduled(fixedDelayString = "${auth.cleanup-interval:PT1H}", initialDelayString = "${auth.cleanup-interval:PT1H}")
    @Transactional
    public void cleanup() {
        var now = clock.instant();
        var cutoff = now.minus(properties.getRetention());
        refreshTokens.deactivateUnusable(now);
        int sessionCount = sessions.revokeExpiredBefore(cutoff, now);
        int tokenCount = refreshTokens.revokeForExpiredSessionsBefore(cutoff, now);
        log.atInfo().addKeyValue("event", "auth_state_revoked").addKeyValue("sessions", sessionCount)
                .addKeyValue("refresh_tokens", tokenCount)
                .log("Expired authentication state revoked; records retained.");
    }
}
