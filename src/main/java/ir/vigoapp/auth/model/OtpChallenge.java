package ir.vigoapp.auth.model;

import lombok.Builder;

import java.time.Instant;

/** Internal Redis state; never serialize this record into an API response or log. */
@Builder
public record OtpChallenge(String token, String identifierKey, String destination, long userId,
                           long credentialVersion, String code, OtpChannel channel, Instant expiresAt,
                           int failedAttempts, String state, boolean passwordVerified) {
    public boolean isOpen(Instant now) {
        return "OPEN".equals(state) && expiresAt.isAfter(now);
    }

    public String authMethod() {
        return passwordVerified ? "PASSWORD_OTP" : "OTP";
    }

    @Override
    public String toString() { return "OtpChallenge[REDACTED]"; }
}
