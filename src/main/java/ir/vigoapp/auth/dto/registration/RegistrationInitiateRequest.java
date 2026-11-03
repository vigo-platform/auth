package ir.vigoapp.auth.dto.registration;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record RegistrationInitiateRequest(@NotBlank @Size(max = 254) String identifier) {
    @Override
    public String toString() { return "RegistrationInitiateRequest[REDACTED]"; }
}
