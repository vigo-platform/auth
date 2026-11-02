package ir.vigoapp.auth.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import ir.vigoapp.auth.dto.ApiResponse;
import ir.vigoapp.auth.dto.ClientInfo;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
public class CustomAuthEntryPointHandler implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    public CustomAuthEntryPointHandler(@Autowired(required = false) ObjectMapper objectMapper) {
        if (objectMapper != null) {
            this.objectMapper = objectMapper;
        } else {
            this.objectMapper = new ObjectMapper().findAndRegisterModules();
        }
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException)
            throws IOException, ServletException {
        var client = ClientInfo.from(request);
        log.atWarn().addKeyValue("event", "authentication_required").addKeyValue("result", "REJECTED")
                .addKeyValue("status", 401).addKeyValue("http_method", request.getMethod())
                .addKeyValue("path", request.getRequestURI()).addKeyValue("ip_address", client.ipAddress())
                .addKeyValue("user_agent", client.userAgent()).addKeyValue("device_id", client.deviceId())
                .log("Request requires authentication.");

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        objectMapper.writeValue(response.getOutputStream(), ApiResponse.failure("UNAUTHORIZED",
                "Authentication is required.", "احراز هویت الزامی است.", null));
    }
}
