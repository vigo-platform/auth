package ir.vigoapp.auth.model.registration;

import ir.vigoapp.auth.model.OtpChannel;
import lombok.Builder;

import java.time.Instant;

/** A verified contact with one account-creation claim; a successful creation consumes it. */
@Builder
public record RegistrationGrant(String token, String identifier, OtpChannel channel, Instant expiresAt,
                                String state) {
    public boolean isOpen() { return "OPEN".equals(state); }
    public boolean isClaimed() { return "CLAIMED".equals(state); }

    @Override
    public String toString() { return "RegistrationGrant[REDACTED]"; }
}
