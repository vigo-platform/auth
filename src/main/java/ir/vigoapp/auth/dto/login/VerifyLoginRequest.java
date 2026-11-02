package ir.vigoapp.auth.dto.login;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifyLoginRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}") @JsonAlias({"mfa", "mfa_token"}) String mfaToken,
        @NotBlank @Pattern(regexp = "[0-9]{6}") String otp
) {
    @Override
    public String toString() { return "VerifyLoginRequest[REDACTED]"; }
}
