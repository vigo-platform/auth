package ir.vigoapp.auth.security;

import ir.vigoapp.auth.config.AuthProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

@Component
public class SecureTokens {
    private final SecureRandom random = new SecureRandom();
    private final SecretKeySpec secret;

    public SecureTokens(AuthProperties properties) {
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(properties.getOtpSecret());
        } catch (IllegalArgumentException | NullPointerException exception) {
            throw new IllegalStateException("auth.otp-secret must be a Base64-encoded secret of at least 32 bytes");
        }
        if (bytes.length < 32) throw new IllegalStateException("auth.otp-secret must contain at least 32 random bytes");
        secret = new SecretKeySpec(bytes, "HmacSHA256");
    }

    public String randomToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String otp() {
        return String.format(java.util.Locale.ROOT, "%06d", random.nextInt(1_000_000));
    }

    public String hash(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    /** Used only to anonymize identifiers in audit logs, never for Redis keys or values. */
    public String fingerprint(String purpose, String value) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(secret);
            return HexFormat.of().formatHex(mac.doFinal((purpose + "\0" + value).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("HMAC-SHA256 is unavailable", exception);
        }
    }
}
