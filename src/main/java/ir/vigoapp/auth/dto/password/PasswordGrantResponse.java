package ir.vigoapp.auth.dto.password;

import lombok.Builder;

@Builder
public record PasswordGrantResponse(String passwordChangeToken, long expiresIn) {
    @Override
    public String toString() { return "PasswordGrantResponse[REDACTED]"; }
}
