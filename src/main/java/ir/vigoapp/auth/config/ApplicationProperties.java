package ir.vigoapp.auth.config;

import ir.vigoapp.auth.entity.OtpChannel;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

@Getter
@Setter
@Validated
@Configuration
@ConfigurationProperties(prefix = "app", ignoreUnknownFields = false)
public class ApplicationProperties {
    private String[] publicPaths = {
            "/.well-known/jwks.json",
            "/actuator/**",
            "/error",
            "/favicon.ico"
    };

    @Valid
    @NotNull
    private UserGrpc userGrpc = new UserGrpc();

    @Valid
    @NotNull
    private AuthDefaults authDefaults = new AuthDefaults();

    /**
     * Initial auth settings used only when no settings record exists.
     *
     * @version 1.0.0
     * @author logTAHA
     */
    @Getter
    @Setter
    public static class AuthDefaults {
        private boolean loginEnabled;
        private boolean registerEnabled;

        @NotNull
        private OtpChannel defaultOtpChannel;

        private boolean emailNotificationEnabled;
        private boolean smsNotificationEnabled;
        private boolean inAppNotificationEnabled;
    }

    @Getter
    @Setter
    public static class UserGrpc {
        @NotBlank
        @Pattern(regexp = "[^\\s/]+", message = "must be a hostname or IP address without a URL scheme")
        private String host;

        @Min(1)
        @Max(65535)
        private int port;

        @Min(1)
        private long timeoutMs = 3000;

    }
}
