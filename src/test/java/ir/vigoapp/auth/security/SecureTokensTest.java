package ir.vigoapp.auth.security;

import ir.vigoapp.auth.config.AuthProperties;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

class SecureTokensTest {
    @Test
    void tokensAreRandomAndOtpHashesAreBoundToTheirChallenge() {
        var properties = new AuthProperties();
        properties.setOtpSecret(Base64.getEncoder().encodeToString(new byte[32]));
        var tokens = new SecureTokens(properties);
        String token = tokens.randomToken();
        assertThat(token).matches("[A-Za-z0-9_-]{43}").isNotEqualTo(tokens.randomToken());
        assertThat(tokens.otp()).matches("[0-9]{6}");
        String hash = tokens.hash(token);
        String codeHash = tokens.fingerprint("login-otp", hash + ":123456");
        assertThat(tokens.matchesOtp(hash, "123456", codeHash)).isTrue();
        assertThat(tokens.matchesOtp(tokens.hash(tokens.randomToken()), "123456", codeHash)).isFalse();
        assertThat(tokens.matchesOtp(hash, "654321", codeHash)).isFalse();
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
