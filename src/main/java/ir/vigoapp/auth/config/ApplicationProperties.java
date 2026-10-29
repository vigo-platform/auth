package ir.vigoapp.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "app")
public class ApplicationProperties {
    private String[] publicPaths = {
            "/.well-known/jwks.json",
            "/actuator/**",
            "/error",
            "/favicon.ico"
    };
}
