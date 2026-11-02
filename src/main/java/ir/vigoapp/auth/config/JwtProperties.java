package ir.vigoapp.auth.config;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    @NotBlank
    private String keyId = "vigo-auth-key-1";
    @NotBlank
    private String privateKeyPath;
    @NotBlank
    private String publicKeyPath;
    @NotBlank
    private String issuer = "auth.vigoapp.ir";
    @NotBlank
    private String audience = "vigo-api";
    @NotNull @DurationMin(seconds = 30)
    private Duration accessTokenTtl = Duration.ofMinutes(15);
}
