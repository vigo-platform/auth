package ir.vigoapp.auth.dto.token;

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
