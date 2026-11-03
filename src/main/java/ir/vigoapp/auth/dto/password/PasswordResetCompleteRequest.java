package ir.vigoapp.auth.dto.password;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record PasswordResetCompleteRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}", message = "Use the password reset token returned by Auth.")
        @JsonAlias("password_reset_token") String passwordResetToken,
        @NotBlank @Size(min = 8, max = 72, message = "Must be between {min} and {max} characters.") String newPassword
) {
    @Override
    public String toString() { return "PasswordResetCompleteRequest[REDACTED]"; }
}
