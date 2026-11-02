package ir.vigoapp.auth.security.login;

import ir.vigoapp.auth.exception.AuthException;
import org.springframework.http.HttpStatus;

import java.util.Locale;

public final class LoginIdentifier {
    private LoginIdentifier() {}

    /** Compare a User response with the canonical lookup identity without trusting its format. */
    public static boolean matches(String normalizedIdentifier, String returnedIdentifier) {
        try {
            return normalizedIdentifier.equals(normalize(returnedIdentifier));
        } catch (AuthException invalidIdentifier) {
            return false;
        }
    }

    public static String normalize(String input) {
        String value = input == null ? "" : input.strip();
        if (value.contains("@")) {
            value = value.toLowerCase(Locale.ROOT);
            if (value.length() <= 254 && value.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+")) return value;
        } else {
            if (value.matches("(?:0098|0)?9[0-9]{9}")) {
                value = "+98" + value.replaceFirst("^(?:0098|0)?", "");
            }
            if (value.matches("\\+[1-9][0-9]{1,14}")) return value;
        }
        throw new AuthException(HttpStatus.BAD_REQUEST, "INVALID_IDENTIFIER",
                "Enter a valid email address or phone number.", "ایمیل یا شماره تلفن معتبر وارد کنید.");
    }
}
