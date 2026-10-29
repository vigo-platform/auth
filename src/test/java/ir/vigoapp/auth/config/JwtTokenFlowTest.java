package ir.vigoapp.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenFlowTest {

    @Test
    @DisplayName("Should sign token with Private Key and verify with Public Key")
    void shouldSignAndVerifyJwtToken() throws Exception {
        RSAPublicKey publicKey = RsaKeyUtils.readPublicKey(".keys/public_key.pem");
        RSAPrivateKey privateKey = RsaKeyUtils.readPrivateKey(".keys/private_key.pem");

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID("vigo-auth-key-1")
                .build();

        JwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
        JwtDecoder decoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();

        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://auth.vigoapp.ir")
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .subject("user-12345")
                .claim("email", "test@vigoapp.ir")
                .build();

        JwsHeader header = JwsHeader.with(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256)
                .keyId("vigo-auth-key-1")
                .build();

        Jwt jwt = encoder.encode(JwtEncoderParameters.from(header, claims));
        assertThat(jwt.getTokenValue()).isNotBlank();

        // Decode and verify with public key
        Jwt decodedJwt = decoder.decode(jwt.getTokenValue());
        assertThat(decodedJwt.getSubject()).isEqualTo("user-12345");
        assertThat(decodedJwt.getClaimAsString("email")).isEqualTo("test@vigoapp.ir");
        assertThat(decodedJwt.getIssuer().toString()).isEqualTo("https://auth.vigoapp.ir");
    }
}
