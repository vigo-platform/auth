package ir.vigoapp.auth.dto.password;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record PasswordChangeInitiateRequest(@NotBlank @Size(max = 72) String currentPassword) {
    @Override
    public String toString() { return "PasswordChangeInitiateRequest[REDACTED]"; }
}
