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
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Slf4j
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper objectMapper;

    public CustomAccessDeniedHandler(@Autowired(required = false) ObjectMapper objectMapper) {
        if (objectMapper != null) {
            this.objectMapper = objectMapper;
        } else {
            this.objectMapper = new ObjectMapper().findAndRegisterModules();
        }
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException, ServletException {
        var client = ClientInfo.from(request);
        log.atWarn().addKeyValue("event", "access_denied").addKeyValue("result", "REJECTED")
                .addKeyValue("status", 403).addKeyValue("http_method", request.getMethod())
                .addKeyValue("path", request.getRequestURI()).addKeyValue("ip_address", client.ipAddress())
                .addKeyValue("user_agent", client.userAgent()).addKeyValue("device_id", client.deviceId())
                .log("Request access denied.");

        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        objectMapper.writeValue(response.getOutputStream(), ApiResponse.failure("ACCESS_DENIED",
                "Access is denied.", "دسترسی مجاز نیست.", null));
    }
}
