package ir.vigoapp.auth.service;

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

    @Scheduled(fixedDelayString = "${auth.cleanup-interval:PT1H}", initialDelayString = "${auth.cleanup-interval:PT1H}")
    @Transactional
    public void cleanup() {
        var now = clock.instant();
        var cutoff = now.minus(properties.getRetention());
        int sessionCount = sessions.revokeExpiredBefore(cutoff, now);
        int tokenCount = refreshTokens.revokeForExpiredSessionsBefore(cutoff, now);
        log.atInfo().addKeyValue("event", "auth_state_revoked").addKeyValue("sessions", sessionCount)
                .addKeyValue("refresh_tokens", tokenCount)
                .log("Expired authentication state revoked; records retained.");
    }
}
