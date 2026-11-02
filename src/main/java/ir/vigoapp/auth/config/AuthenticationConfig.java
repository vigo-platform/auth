package ir.vigoapp.auth.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.util.Map;

@Configuration
@EnableScheduling
@EnableConfigurationProperties(AuthProperties.class)
public class AuthenticationConfig {
    @Bean
    public Clock authClock() {
        return Clock.systemUTC();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        var bcrypt = new BCryptPasswordEncoder(12);
        var encoder = new DelegatingPasswordEncoder("bcrypt", Map.of("bcrypt", bcrypt));
        encoder.setDefaultPasswordEncoderForMatches(bcrypt);
        return encoder;
    }
}
