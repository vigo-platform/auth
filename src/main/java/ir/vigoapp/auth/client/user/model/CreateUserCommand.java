package ir.vigoapp.auth.client.user.model;

import lombok.Builder;

/** Signup data with a password hash already encoded by Auth. */
@Builder
public record CreateUserCommand(
        String email,
        String phone,
        String firstName,
        String lastName,
        String passwordHash
) {
    @Override
    public String toString() {
        return "CreateUserCommand[REDACTED]";
    }
}
