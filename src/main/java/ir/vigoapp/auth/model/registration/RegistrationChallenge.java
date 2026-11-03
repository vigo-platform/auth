package ir.vigoapp.auth.model.registration;

import ir.vigoapp.auth.model.OtpChannel;
import lombok.Builder;

import java.time.Instant;

/** Guest OTP metadata. The code stays inside Redis and the notification boundary. */
@Builder
public record RegistrationChallenge(String token, String identifier, OtpChannel channel,
                                    Instant expiresAt, int failedAttempts) {
    @Override
    public String toString() { return "RegistrationChallenge[REDACTED]"; }
}
