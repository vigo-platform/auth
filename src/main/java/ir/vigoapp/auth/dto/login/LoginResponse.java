package ir.vigoapp.auth.dto.login;

import com.fasterxml.jackson.annotation.JsonInclude;
import ir.vigoapp.auth.dto.token.TokenResponse;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record LoginResponse(String step, TokenResponse tokens, OtpChallengeResponse challenge) {
    public static LoginResponse authenticated(TokenResponse tokens) {
        return new LoginResponse("SUCCESS", tokens, null);
    }

    public static LoginResponse otpRequired(OtpChallengeResponse challenge) {
        return new LoginResponse("OTP_REQUIRED", null, challenge);
    }

    @Override
    public String toString() { return "LoginResponse[step=" + step + ", REDACTED]"; }
}
