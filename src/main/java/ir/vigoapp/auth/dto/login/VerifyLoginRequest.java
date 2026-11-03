package ir.vigoapp.auth.dto.login;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;

@Builder
public record VerifyLoginRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}", message = "Use the token returned when requesting the code.")
        @JsonAlias({"mfa", "mfa_token"}) String mfaToken,
        @NotBlank @Pattern(regexp = "[0-9]{6}", message = "Must be a 6-digit code.") String otp
) {
    @Override
    public String toString() { return "VerifyLoginRequest[REDACTED]"; }
}
