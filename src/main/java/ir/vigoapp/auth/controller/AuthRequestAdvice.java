package ir.vigoapp.auth.controller;

import ir.vigoapp.auth.dto.ClientInfo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/** Shared cache policy and safe request auditing for authentication workflows. */
@ControllerAdvice(assignableTypes = {LoginController.class, RegistrationController.class, PasswordLifecycleController.class})
@Slf4j
public class AuthRequestAdvice {
    @ModelAttribute
    public void prepareRequest(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        var client = ClientInfo.from(request);
        log.atInfo().addKeyValue("event", "auth_request_received")
                .addKeyValue("http_method", request.getMethod()).addKeyValue("path", request.getRequestURI())
                .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                .addKeyValue("device_id", client.deviceId()).log("Authentication request received.");
    }
}
