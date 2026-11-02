package ir.vigoapp.auth.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public final class AuthException extends RuntimeException {
    private final HttpStatus status;
    private final String code;
    private final String messageFa;
    private final long retryAfterSeconds;

    public AuthException(HttpStatus status, String code, String message, String messageFa) {
        this(status, code, message, messageFa, 0);
    }

    public AuthException(HttpStatus status, String code, String message, String messageFa, long retryAfterSeconds) {
        super(message);
        this.status = status;
        this.code = code;
        this.messageFa = messageFa;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public static AuthException invalidCredentials() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "INVALID_CREDENTIALS",
                "The credentials are invalid or login is unavailable for this account.",
                "اطلاعات ورود نامعتبر است یا ورود به این حساب امکان‌پذیر نیست.");
    }

    public static AuthException invalidOtp() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "INVALID_OTP",
                "The verification code or challenge is invalid, expired, or already used.",
                "کد یا درخواست تأیید نامعتبر، منقضی یا قبلاً استفاده شده است.");
    }

    public static AuthException invalidRefreshToken() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "INVALID_REFRESH_TOKEN",
                "The session is invalid or expired. Please log in again.",
                "نشست نامعتبر یا منقضی است. دوباره وارد شوید.");
    }
}
