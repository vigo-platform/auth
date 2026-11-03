package ir.vigoapp.auth.dto.registration;

import ir.vigoapp.auth.model.OtpChannel;
import lombok.Builder;

@Builder
public record RegistrationInitiateResponse(String mfaToken, OtpChannel channel, long expiresIn, long resendAfter) {
    @Override
    public String toString() { return "RegistrationInitiateResponse[REDACTED]"; }
}
