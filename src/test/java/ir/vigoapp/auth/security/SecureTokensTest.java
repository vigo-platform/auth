package ir.vigoapp.auth.security;

import ir.vigoapp.auth.config.AuthProperties;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

class SecureTokensTest {
    @Test
    void tokensStayRandomAndDatabaseHashesAndAuditFingerprintsRemainAvailable() {
        var properties = new AuthProperties();
        properties.setOtpSecret(Base64.getEncoder().encodeToString(new byte[32]));
        var tokens = new SecureTokens(properties);
        String token = tokens.randomToken();
        assertThat(token).matches("[A-Za-z0-9_-]{43}").isNotEqualTo(tokens.randomToken());
        assertThat(tokens.otp()).matches("[0-9]{6}");
        assertThat(tokens.hash(token)).matches("[0-9a-f]{64}").isNotEqualTo(token);
        assertThat(tokens.hash("abc")).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assertThat(tokens.fingerprint("identifier", "user@example.com"))
                .matches("[0-9a-f]{64}").isNotEqualTo(tokens.fingerprint("account", "user@example.com"));
    }

    @Test
    void rejectsMissingMalformedAndShortSecrets() {
        var properties = new AuthProperties();
        assertThatThrownBy(() -> new SecureTokens(properties)).isInstanceOf(IllegalStateException.class);
        properties.setOtpSecret("bad-secret");
        assertThatThrownBy(() -> new SecureTokens(properties)).isInstanceOf(IllegalStateException.class);
        properties.setOtpSecret(Base64.getEncoder().encodeToString(new byte[16]));
        assertThatThrownBy(() -> new SecureTokens(properties)).isInstanceOf(IllegalStateException.class);
    }
}
