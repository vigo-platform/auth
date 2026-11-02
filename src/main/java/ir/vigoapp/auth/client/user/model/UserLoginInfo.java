package ir.vigoapp.auth.client.user.model;

import lombok.Builder;

/** Contains a credential hash: internal use only, never return from a controller. */
@Builder
public record UserLoginInfo(UserAccount user, String passwordHash) {
    @Override
    public String toString() {
        return "UserLoginInfo[REDACTED]";
    }
}
