package ir.vigoapp.auth.config;

import ir.vigoapp.auth.security.handler.CustomAccessDeniedHandler;
import ir.vigoapp.auth.security.handler.CustomAuthEntryPointHandler;
import ir.vigoapp.auth.security.jwt.JwtAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * <h2>Core Security Configuration</h2>
 * <p>
 * Configures the main <b>SecurityFilterChain</b>. This class applies our custom
 * JWT filter, exception handlers (401 & 403), and dictates the session management policy.
 * </p>
 * <ul>
 *   <li><i>CSRF:</i> Disabled for stateless APIs.</li>
 *   <li><i>Session:</i> Completely Stateless.</li>
 *   <li><i>Public Paths:</i> Dynamically loaded from application properties.</li>
 * </ul>
 *
 * @since 1.0.0
 * @version 1.0.0
 * @author logTAHA
 */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final CustomAuthEntryPointHandler customAuthEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final ApplicationProperties applicationProperties;

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilterRegistration() {
        // Run only inside Spring Security, rather than twice as a servlet filter as well.
        var registration = new FilterRegistrationBean<>(jwtAuthenticationFilter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        String[] publicEndpoints = applicationProperties.getPublicPaths();
        log.atInfo().addKeyValue("event", "security_chain_initialized").addKeyValue("session_policy", "stateless")
                .addKeyValue("public_path_count", publicEndpoints.length).log("Security filter chain initialized.");

        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(customAuthEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
                )
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.POST,
                                "/api/v1/auth/password/expired/complete",
                                "/api/v1/auth/password/reset/initiate",
                                "/api/v1/auth/password/reset/verify",
                                "/api/v1/auth/password/reset/complete").permitAll()
                        .requestMatchers("/api/v1/auth/password/**").authenticated()
                        .requestMatchers(publicEndpoints).permitAll()
                        .anyRequest().authenticated()
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
