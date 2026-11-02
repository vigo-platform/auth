package ir.vigoapp.auth.security.login;

import ir.vigoapp.auth.exception.AuthException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import static org.assertj.core.api.Assertions.*;

class LoginIdentifierTest {
    @ParameterizedTest
    @ValueSource(strings = {"09123456789", "9123456789", "00989123456789", "+989123456789"})
    void normalizesIranianPhoneVariants(String value) {
        assertThat(LoginIdentifier.normalize(value)).isEqualTo("+989123456789");
    }

    @ParameterizedTest
    @ValueSource(strings = {"09111111111", "9111111111", "00989111111111", "+989111111111"})
    void acceptsEquivalentUserResponsePhoneFormats(String value) {
        assertThat(LoginIdentifier.matches("+989111111111", value)).isTrue();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"bad", "09111111112", "user@example.com"})
    void doesNotAcceptAMissingInvalidOrDifferentUserResponsePhone(String value) {
        assertThat(LoginIdentifier.matches("+989111111111", value)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"USER@EXAMPLE.COM", " user@example.com "})
    void canonicalizesEmail(String value) {
        assertThat(LoginIdentifier.normalize(value)).isEqualTo("user@example.com");
    }

    @ParameterizedTest
    @ValueSource(strings = {"bad", "user@", "a b@example.com", "user@example.com\r\nforged", "++989123456789", "+0123"})
    void rejectsInvalidIdentifiers(String value) {
        assertThatThrownBy(() -> LoginIdentifier.normalize(value)).isInstanceOf(AuthException.class);
    }
}
