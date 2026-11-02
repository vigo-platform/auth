package ir.vigoapp.auth.service.login;

import ir.vigoapp.auth.exception.AuthException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.*;

class LoginIdentifierTest {
    @ParameterizedTest
    @ValueSource(strings = {"09123456789", "9123456789", "00989123456789", "+989123456789"})
    void normalizesIranianPhoneVariants(String value) {
        assertThat(LoginIdentifier.normalize(value)).isEqualTo("+989123456789");
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
