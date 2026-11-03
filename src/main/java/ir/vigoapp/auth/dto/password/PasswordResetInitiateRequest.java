package ir.vigoapp.auth.dto.password;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record PasswordResetInitiateRequest(@NotBlank @Size(max = 254) String identifier) {
    @Override
    public String toString() { return "PasswordResetInitiateRequest[REDACTED]"; }
}
