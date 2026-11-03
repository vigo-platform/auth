package ir.vigoapp.auth.dto.password;

import lombok.Builder;

@Builder
public record PasswordResetGrantResponse(String passwordResetToken, long expiresIn) {
    @Override
    public String toString() { return "PasswordResetGrantResponse[REDACTED]"; }
}
