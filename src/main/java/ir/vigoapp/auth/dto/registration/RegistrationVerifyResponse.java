package ir.vigoapp.auth.dto.registration;

import lombok.Builder;

@Builder
public record RegistrationVerifyResponse(String registrationToken, long expiresIn) {
    @Override
    public String toString() { return "RegistrationVerifyResponse[REDACTED]"; }
}
