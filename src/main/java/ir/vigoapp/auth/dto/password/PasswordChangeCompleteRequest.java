package ir.vigoapp.auth.dto.password;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record PasswordChangeCompleteRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}", message = "Use the password change token returned by Auth.")
        @JsonAlias("password_change_token") String passwordChangeToken,
        @NotBlank @Size(min = 8, max = 72, message = "Must be between {min} and {max} characters.") String newPassword
) {
    @Override
    public String toString() { return "PasswordChangeCompleteRequest[REDACTED]"; }
}
