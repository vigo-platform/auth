package ir.vigoapp.auth.dto.login;

import com.fasterxml.jackson.annotation.JsonInclude;
import ir.vigoapp.auth.dto.password.PasswordGrantResponse;
import ir.vigoapp.auth.dto.token.TokenResponse;
import lombok.Builder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
public record LoginResponse(String step, TokenResponse tokens, OtpChallengeResponse challenge,
                            PasswordGrantResponse passwordChange) {
    public static LoginResponse authenticated(TokenResponse tokens) {
        return LoginResponse.builder().step("SUCCESS").tokens(tokens).build();
    }

    public static LoginResponse otpRequired(OtpChallengeResponse challenge) {
        return LoginResponse.builder().step("OTP_REQUIRED").challenge(challenge).build();
    }

    public static LoginResponse passwordChangeRequired(PasswordGrantResponse passwordChange) {
        return LoginResponse.builder().step("PASSWORD_CHANGE_REQUIRED").passwordChange(passwordChange).build();
    }

    public static LoginResponse passwordUpdatedLoginRequired() {
        return LoginResponse.builder().step("PASSWORD_UPDATED_LOGIN_REQUIRED").build();
    }

    @Override
    public String toString() { return "LoginResponse[step=" + step + ", REDACTED]"; }
}
