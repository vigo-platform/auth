package ir.vigoapp.auth.client.user.model;

import lombok.Builder;

import java.util.List;

/** Null email/phone means the corresponding identifier is absent. */
@Builder(toBuilder = true)
public record UserAccount(
        long userId,
        List<String> roles,
        String email,
        String phone,
        AccountStatus status,
        boolean emailVerified,
        boolean phoneVerified,
        long credentialVersion,
        boolean credentialsExpired,
        boolean twoFactorEnabled) {
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
