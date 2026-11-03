package ir.vigoapp.auth.controller;

import ir.vigoapp.auth.config.ApplicationProperties;
import ir.vigoapp.auth.config.SecurityConfig;
import ir.vigoapp.auth.exception.GlobalExceptionHandler;
import ir.vigoapp.auth.security.handler.CustomAccessDeniedHandler;
import ir.vigoapp.auth.security.handler.CustomAuthEntryPointHandler;
import ir.vigoapp.auth.security.jwt.JwtAuthenticationFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.junit.jupiter.web.SpringJUnitWebConfig;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringJUnitWebConfig(PasswordLifecycleControllerTest.WebConfig.class)
class PasswordLifecycleControllerTest {
    private static final String BASE = "/api/v1/auth/password";

    @Autowired
    private WebApplicationContext context;

    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void changePathsRequireBearerEvenWithBroadConfiguredPublicPaths() throws Exception {
        for (String step : new String[]{"initiate", "verify", "complete"}) {
            mvc.perform(post(BASE + "/change/" + step).contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                    .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"));
        }
    }

    @Test
    void guestPasswordPathsReachRequestValidationWithoutBearer() throws Exception {
        for (String path : new String[]{"/reset/initiate", "/reset/verify", "/reset/complete", "/expired/complete"}) {
            mvc.perform(post(BASE + path).contentType(MediaType.APPLICATION_JSON).content("{}"))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                    .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"));
        }
    }

    @Test
    void invalidNewPasswordDoesNotExposeTheSubmittedCredentials() throws Exception {
        String token = "A".repeat(43);
        mvc.perform(post(BASE + "/reset/complete").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"passwordResetToken":"%s","newPassword":"secret"}
                                """.formatted(token)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                .andExpect(jsonPath("$.data.errors.newPassword").value("Must be between 8 and 72 characters."))
                .andExpect(content().string(not(containsString("secret"))))
                .andExpect(content().string(not(containsString(token))));
    }

    @Configuration
    @EnableWebMvc
    @Import({SecurityConfig.class, JwtAuthenticationFilter.class, CustomAuthEntryPointHandler.class,
            CustomAccessDeniedHandler.class, AuthRequestAdvice.class, GlobalExceptionHandler.class})
    static class WebConfig {
        @Bean
        PasswordLifecycleController passwordLifecycleController() {
            return new PasswordLifecycleController(null);
        }

        @Bean
        JwtDecoder jwtDecoder() {
            return token -> { throw new AssertionError("No bearer token supplied"); };
        }

        @Bean
        ApplicationProperties applicationProperties() {
            var properties = new ApplicationProperties();
            properties.setPublicPaths(new String[]{"/api/v1/auth/**"});
            return properties;
        }
    }
}
