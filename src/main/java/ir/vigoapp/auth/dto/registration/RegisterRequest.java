package ir.vigoapp.auth.dto.registration;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record RegisterRequest(
        @Size(max = 254) String email,
        @Size(max = 32) String phone,
        @NotBlank @Size(min = 8, max = 72) String password,
        @Size(max = 100) String firstName,
        @Size(max = 100) String lastName
) {
    @Override
    public String toString() { return "RegisterRequest[REDACTED]"; }
}
