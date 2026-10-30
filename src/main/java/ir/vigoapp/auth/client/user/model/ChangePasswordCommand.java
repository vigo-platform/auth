package ir.vigoapp.auth.client.user.model;

/** Caller authorizes change/reset before sending the encoded password hash. */
public record ChangePasswordCommand(
        long userId,
        String newPasswordHash,
        long expectedCredentialVersion
) {
    @Override
    public String toString() {
        return "ChangePasswordCommand[REDACTED]";
    }
}
