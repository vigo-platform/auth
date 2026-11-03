package ir.vigoapp.auth.dto.registration;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;

@Builder
public record RegistrationVerifyRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}") @JsonAlias({"mfa", "mfa_token"}) String mfaToken,
        @NotBlank @Pattern(regexp = "[0-9]{6}") String otp
) {
    @Override
    public String toString() { return "RegistrationVerifyRequest[REDACTED]"; }
}
