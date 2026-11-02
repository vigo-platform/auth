package ir.vigoapp.auth.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import ir.vigoapp.auth.security.jwt.RsaKeyUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTypeValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

@Configuration
@RequiredArgsConstructor
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {

    private final JwtProperties jwtProperties;

    @Bean
    public RSAKey rsaKey() {
        RSAPublicKey publicKey = RsaKeyUtils.readPublicKey(jwtProperties.getPublicKeyPath());
        RSAPrivateKey privateKey = RsaKeyUtils.readPrivateKey(jwtProperties.getPrivateKeyPath());

        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(jwtProperties.getKeyId())
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        // Spring validates signatures with RS256 only; issuer/audience/type and required claims are explicit.
        var decoder = NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).validateType(false).build();
        OAuth2TokenValidator<Jwt> claims = jwt -> {
            try {
                UUID.fromString(jwt.getClaimAsString("sid"));
                Number version = jwt.getClaim("credential_version");
                Object roles = jwt.getClaims().get("roles");
                boolean valid = "at+jwt".equals(jwt.getHeaders().get("typ"))
                        && jwt.getAudience().contains(jwtProperties.getAudience())
                        && Long.parseLong(jwt.getSubject()) > 0 && version != null && version.longValue() > 0
                        && jwt.getExpiresAt() != null && jwt.getIssuedAt() != null && jwt.getId() != null
                        && jwt.getExpiresAt().isAfter(jwt.getIssuedAt())
                        && roles instanceof List<?> values && values.stream().allMatch(role -> role instanceof String text && !text.isBlank());
                if (valid) return OAuth2TokenValidatorResult.success();
            } catch (IllegalArgumentException | NullPointerException | ClassCastException ignored) {
                // Malformed claims are authentication failures, never application errors.
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid access token claims", null));
        };
        decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(
                new JwtIssuerValidator(jwtProperties.getIssuer()), new JwtTypeValidator("at+jwt"),
                new JwtClaimValidator<String>("token_use", "access"::equals), claims));
        return decoder;
    }
}
