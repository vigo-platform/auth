package ir.vigoapp.auth.service.login;

import ir.vigoapp.auth.entity.OtpChannel;
import java.time.Instant;

/** Internal Redis state; never serialize this record into an API response or log. */
public record OtpChallenge(String token, String identifierKey, String destination, long userId,
                           long credentialVersion, String code, OtpChannel channel, Instant expiresAt,
                           int failedAttempts, String state) {
    public boolean isOpen(Instant now) {
        return "OPEN".equals(state) && expiresAt.isAfter(now);
    }

    @Override
    public String toString() { return "OtpChallenge[REDACTED]"; }
}
