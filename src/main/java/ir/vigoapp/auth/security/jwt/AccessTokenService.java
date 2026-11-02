package ir.vigoapp.auth.security.jwt;

import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.config.JwtProperties;
import ir.vigoapp.auth.entity.AuthSession;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AccessTokenService {
    private final JwtEncoder encoder;
    private final JwtProperties properties;

    public Jwt issue(UserAccount user, AuthSession session, Instant now) {
        Instant expires = now.plus(properties.getAccessTokenTtl());
        if (expires.isAfter(session.getExpiresAt())) expires = session.getExpiresAt();
        var claims = JwtClaimsSet.builder()
                .issuer(properties.getIssuer()).audience(List.of(properties.getAudience()))
                .subject(Long.toString(user.userId())).issuedAt(now).notBefore(now).expiresAt(expires)
                .id(UUID.randomUUID().toString())
                .claim("token_use", "access")
                .claim("sid", session.getId().toString())
                .claim("credential_version", user.credentialVersion())
                .claim("roles", user.roles()).build();
        var header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(properties.getKeyId()).type("at+jwt").build();
        return encoder.encode(JwtEncoderParameters.from(header, claims));
    }
}
