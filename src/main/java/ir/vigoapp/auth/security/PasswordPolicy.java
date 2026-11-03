package ir.vigoapp.auth.security;

import ir.vigoapp.auth.exception.AuthException;
import org.springframework.http.HttpStatus;

import java.nio.charset.StandardCharsets;

public final class PasswordPolicy {
    private PasswordPolicy() {}

    public static void validateNewPassword(String password) {
        if (password == null || password.isBlank() || password.length() < 8) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "INVALID_REQUEST",
                    "Password must contain at least 8 characters.", "رمز عبور باید حداقل ۸ کاراکتر داشته باشد.");
        }
        requireBcryptLength(password);
    }

    public static void requireBcryptLength(String password) {
        if (password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "INVALID_PASSWORD_LENGTH",
                    "Password must not exceed 72 UTF-8 bytes.", "طول رمز عبور نباید بیش از ۷۲ بایت باشد.");
        }
    }
}
