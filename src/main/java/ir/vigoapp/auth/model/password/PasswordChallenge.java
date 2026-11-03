package ir.vigoapp.auth.model.password;

import ir.vigoapp.auth.model.OtpChannel;
import lombok.Builder;

import java.time.Instant;
import java.util.UUID;

@Builder
public record PasswordChallenge(PasswordPurpose purpose, long userId, long credentialVersion, UUID sessionId,
                                String identifierKey, OtpChannel channel, String destination,
                                OtpChannel previousChannel, String previousDestination, Instant expiresAt) {
    @Override
    public String toString() {
        return "PasswordChallenge[REDACTED]";
    }
}
