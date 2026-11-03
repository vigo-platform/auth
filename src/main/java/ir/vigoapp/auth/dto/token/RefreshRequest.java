package ir.vigoapp.auth.dto.token;

import com.fasterxml.jackson.annotation.JsonAlias;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;

@Builder
public record RefreshRequest(
        @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{43}", message = "Use the refresh token returned by login or refresh.")
        @JsonAlias("refresh_token") String refreshToken
) {
    @Override
    public String toString() { return "RefreshRequest[REDACTED]"; }
}
