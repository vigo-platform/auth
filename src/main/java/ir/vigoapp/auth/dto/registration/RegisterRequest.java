package ir.vigoapp.auth.dto.registration;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record RegisterRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}", message = "Use the registration token returned by verification.")
        @JsonAlias("registration_token") String registrationToken,
        @NotBlank @Size(min = 8, max = 72, message = "Must be between {min} and {max} characters.") String password,
        @Size(max = 100) String firstName,
        @Size(max = 100) String lastName
) {
    @Override
    public String toString() { return "RegisterRequest[REDACTED]"; }
}
