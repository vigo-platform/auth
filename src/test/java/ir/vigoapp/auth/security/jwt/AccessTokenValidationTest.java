package ir.vigoapp.auth.security.jwt;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.config.JwtConfig;
import ir.vigoapp.auth.config.JwtProperties;
import ir.vigoapp.auth.entity.AuthSession;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.util.ReflectionTestUtils;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

class AccessTokenValidationTest {
    private static JwtEncoder encoder;
    private static JwtDecoder decoder;
    private static JwtProperties properties;

    @BeforeAll
    static void keys() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        var pair = generator.generateKeyPair();
        var key = new RSAKey.Builder((RSAPublicKey) pair.getPublic()).privateKey((RSAPrivateKey) pair.getPrivate())
                .keyID("test-key").build();
        properties = new JwtProperties();
        properties.setKeyId("test-key");
        encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
        decoder = new JwtConfig(properties).jwtDecoder(key);
    }

    @Test
    void issuedAccessTokenPassesTheActualDecoder() {
        var now = Instant.now();
        var user = new UserAccount(42, List.of("USER", "ADMIN"), "user@example.com", null,
                UserAccount.AccountStatus.ACTIVE, true, false, 3, false, false);
        var session = new AuthSession(user, now, now.plusSeconds(86400));
        ReflectionTestUtils.setField(session, "id", UUID.randomUUID());
        var issued = new AccessTokenService(encoder, properties).issue(user, session, now);
        var jwt = decoder.decode(issued.getTokenValue());
        assertThat(jwt.getSubject()).isEqualTo("42");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("USER", "ADMIN");
        assertThat(jwt.getClaimAsString("sid")).isEqualTo(session.getId().toString());
    }

    @Test
    void rejectsWrongIssuerAudienceAndTokenUse() {
        assertRejected(valid().issuer("https://other.example"));
        assertRejected(valid().audience(List.of("other-api")));
        assertRejected(valid().claim("token_use", "refresh"));
    }

    @Test
    void rejectsMissingExpirySessionOrCredentialVersion() {
        assertRejected(valid().claims(values -> values.remove("exp")));
        assertRejected(valid().claims(values -> values.remove("sid")));
        assertRejected(valid().claim("credential_version", "malformed"));
    }

    @Test
    void rejectsExpiredTokensAndIncorrectType() {
        assertRejected(valid().issuedAt(Instant.now().minusSeconds(900)).expiresAt(Instant.now().minusSeconds(1)));
        var header = JwsHeader.with(SignatureAlgorithm.RS256).keyId("test-key").type("JWT").build();
        String value = encoder.encode(JwtEncoderParameters.from(header, valid().build())).getTokenValue();
        assertThatThrownBy(() -> decoder.decode(value)).isInstanceOf(JwtException.class);
    }

    private JwtClaimsSet.Builder valid() {
        var now = Instant.now();
        return JwtClaimsSet.builder().issuer(properties.getIssuer()).audience(List.of(properties.getAudience()))
                .subject("42").issuedAt(now).expiresAt(now.plusSeconds(300)).id(UUID.randomUUID().toString())
                .claim("token_use", "access").claim("sid", UUID.randomUUID().toString())
                .claim("credential_version", 3).claim("roles", List.of("USER"));
    }

    private void assertRejected(JwtClaimsSet.Builder claims) {
        var header = JwsHeader.with(SignatureAlgorithm.RS256).keyId("test-key").type("at+jwt").build();
        var value = encoder.encode(JwtEncoderParameters.from(header, claims.build())).getTokenValue();
        assertThatThrownBy(() -> decoder.decode(value)).isInstanceOf(JwtException.class);
    }
}
