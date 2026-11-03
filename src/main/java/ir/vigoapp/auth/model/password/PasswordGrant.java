package ir.vigoapp.auth.model.password;

import ir.vigoapp.auth.model.OtpChannel;
import lombok.Builder;

import java.time.Instant;
import java.util.UUID;

@Builder
public record PasswordGrant(PasswordPurpose purpose, long userId, long credentialVersion, UUID sessionId,
                            boolean passwordVerified, OtpChannel channel, String destination,
                            OtpChannel otherChannel, String otherDestination, Instant expiresAt, String state) {
    public boolean isOpen() {
        return "OPEN".equals(state);
    }

    public boolean isClaimed() {
        return "CLAIMED".equals(state);
    }

    @Override
    public String toString() {
        return "PasswordGrant[REDACTED]";
    }
}
