package ir.vigoapp.auth.client.user.model;

import java.util.List;

/** Null email/phone means the corresponding identifier is absent. */
public record UserAccount(
        long userId,
        List<String> roles,
        String email,
        String phone,
        AccountStatus status,
        boolean emailVerified,
        boolean phoneVerified,
        long credentialVersion,
        boolean credentialsExpired) {
    public UserAccount {
        roles = List.copyOf(roles);
    }

    public enum AccountStatus {
        UNKNOWN,
        PENDING_VERIFICATION,
        ACTIVE,
        SUSPENDED,
        DEACTIVATED
    }
}
