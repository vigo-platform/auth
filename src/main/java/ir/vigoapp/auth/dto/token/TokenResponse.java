package ir.vigoapp.auth.dto.token;

import lombok.Builder;

@Builder
public record TokenResponse(
        String tokenType,
        String accessToken,
        long accessExpiresIn,
        String refreshToken,
        long refreshExpiresIn
) {
    @Override
    public String toString() { return "TokenResponse[REDACTED]"; }
}
