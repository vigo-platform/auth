package ir.vigoapp.auth.dto.password;

import com.fasterxml.jackson.annotation.JsonInclude;
import ir.vigoapp.auth.dto.login.OtpChallengeResponse;
import lombok.Builder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
public record PasswordStepResponse(
        String step,
        OtpChallengeResponse challenge,
        PasswordGrantResponse passwordChange,
        PasswordResetGrantResponse passwordReset
) {
    public static PasswordStepResponse otpRequired(OtpChallengeResponse challenge) {
        return PasswordStepResponse.builder().step("OTP_REQUIRED").challenge(challenge).build();
    }

    public static PasswordStepResponse changeRequired(PasswordGrantResponse grant) {
        return PasswordStepResponse.builder().step("PASSWORD_CHANGE_REQUIRED").passwordChange(grant).build();
    }

    public static PasswordStepResponse resetRequired(String token, long expiresIn) {
        return PasswordStepResponse.builder().step("PASSWORD_RESET_REQUIRED")
                .passwordReset(PasswordResetGrantResponse.builder().passwordResetToken(token).expiresIn(expiresIn).build())
                .build();
    }

    public static PasswordStepResponse updatedLoginRequired() {
        return PasswordStepResponse.builder().step("PASSWORD_UPDATED_LOGIN_REQUIRED").build();
    }

    @Override
    public String toString() { return "PasswordStepResponse[step=" + step + ", REDACTED]"; }
}
