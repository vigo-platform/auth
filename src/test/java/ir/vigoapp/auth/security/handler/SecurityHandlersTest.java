package ir.vigoapp.auth.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityHandlersTest {

    @Test
    @DisplayName("CustomAuthEntryPointHandler should return 401 JSON")
    void testAuthEntryPoint() throws Exception {
        CustomAuthEntryPointHandler handler = new CustomAuthEntryPointHandler(new ObjectMapper());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/protected");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.commence(request, response, new BadCredentialsException("Bad token"));

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).contains("application/json");

        Map<?, ?> body = new ObjectMapper().readValue(response.getContentAsString(), Map.class);
        assertThat(body.get("success")).isEqualTo(false);
        assertThat(body.get("code")).isEqualTo("UNAUTHORIZED");
        assertThat(body.get("messageFa")).isEqualTo("احراز هویت الزامی است.");
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
        assertThat(response.getContentAsString()).doesNotContain("Bad token");
    }

    @Test
    @DisplayName("CustomAccessDeniedHandler should return 403 JSON")
    void testAccessDeniedHandler() throws Exception {
        CustomAccessDeniedHandler handler = new CustomAccessDeniedHandler(null); // test fallback
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/admin");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handle(request, response, new AccessDeniedException("Access denied"));

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).contains("application/json");

        Map<?, ?> body = new ObjectMapper().readValue(response.getContentAsString(), Map.class);
        assertThat(body.get("success")).isEqualTo(false);
        assertThat(body.get("code")).isEqualTo("ACCESS_DENIED");
        assertThat(body.get("messageFa")).isEqualTo("دسترسی مجاز نیست.");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    }
}
