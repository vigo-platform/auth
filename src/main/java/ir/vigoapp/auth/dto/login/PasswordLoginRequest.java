package ir.vigoapp.auth.dto.login;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record PasswordLoginRequest(
        @NotBlank @Size(max = 254) String identifier,
        @NotBlank @Size(max = 72) String password
) {
    @Override
    public String toString() { return "PasswordLoginRequest[REDACTED]"; }
}
