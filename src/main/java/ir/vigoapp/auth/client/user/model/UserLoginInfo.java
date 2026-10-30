package ir.vigoapp.auth.client.user.model;

/** Contains a credential hash: internal use only, never return from a controller. */
public record UserLoginInfo(UserAccount user, String passwordHash) {
    @Override
    public String toString() {
        return "UserLoginInfo[REDACTED]";
    }
}
