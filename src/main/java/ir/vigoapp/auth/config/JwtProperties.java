package ir.vigoapp.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String keyId = "vigo-auth-key-1";
    private String privateKeyPath;
    private String publicKeyPath;
}
