package ir.vigoapp.auth.controller;

import ir.vigoapp.auth.exception.GlobalExceptionHandler;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class RegistrationControllerValidationTest {
    private final MockMvc mvc = MockMvcBuilders.standaloneSetup(new RegistrationController(null))
            .setControllerAdvice(new GlobalExceptionHandler()).build();

    @Test
    void explainsShortPasswordWithoutEchoingCredentials() throws Exception {
        String token = "A".repeat(43);
        mvc.perform(post("/api/v1/auth/register/complete").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"registrationToken":"%s","password":"example","firstName":"Test","lastName":"User"}
                                """.formatted(token)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                .andExpect(jsonPath("$.data.errors", aMapWithSize(1)))
                .andExpect(jsonPath("$.data.errors.password").value("Must be between 8 and 72 characters."))
                .andExpect(content().string(not(containsString("example"))))
                .andExpect(content().string(not(containsString(token))));
    }

    @Test
    void distinguishesMissingFieldsAndInvalidFormats() throws Exception {
        mvc.perform(post("/api/v1/auth/register/verify").contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"mfaToken":"","otp":"secret"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.data.errors.mfaToken").value("This field is required."))
                .andExpect(jsonPath("$.data.errors.otp").value("Must be a 6-digit code."))
                .andExpect(content().string(not(containsString("secret"))));
    }

    @Test
    void explainsUnreadableJsonWithoutEchoingItsContent() throws Exception {
        mvc.perform(post("/api/v1/auth/register/complete").contentType(MediaType.APPLICATION_JSON)
                        .content("{broken-secret"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                .andExpect(jsonPath("$.message").value("Send a valid JSON body with the expected field types."))
                .andExpect(content().string(not(containsString("broken-secret"))));
    }
}
