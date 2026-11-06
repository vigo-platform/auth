package ir.vigoapp.auth.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Collections;
import java.util.Locale;
import java.util.Objects;
import java.util.UUID;

public record OtpNotificationContext(UUID correlationId, String locale) {
    private static final String ATTRIBUTE = OtpNotificationContext.class.getName();

    public OtpNotificationContext {
        Objects.requireNonNull(correlationId);
        if (!isSupported(locale)) throw new IllegalArgumentException("Unsupported OTP locale");
    }

    static OtpNotificationContext current() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) {
            return new OtpNotificationContext(UUID.randomUUID(), "fa");
        }
        var request = attributes.getRequest();
        if (request.getAttribute(ATTRIBUTE) instanceof OtpNotificationContext context) return context;
        var context = new OtpNotificationContext(correlationId(request.getHeader("X-Correlation-ID")), locale(request));
        request.setAttribute(ATTRIBUTE, context);
        return context;
    }

    private static UUID correlationId(String value) {
        if (value != null && value.length() == 36) {
            try {
                var id = UUID.fromString(value);
                if (id.toString().equalsIgnoreCase(value)) return id;
            } catch (IllegalArgumentException ignored) {
                // Malformed client headers get a server-generated correlation ID.
            }
        }
        return UUID.randomUUID();
    }

    private static String locale(HttpServletRequest request) {
        if (request.getHeader(HttpHeaders.ACCEPT_LANGUAGE) == null) return "fa";
        return Collections.list(request.getLocales()).stream().map(Locale::getLanguage)
                .filter(OtpNotificationContext::isSupported).findFirst().orElse("fa");
    }

    private static boolean isSupported(String language) {
        return "fa".equals(language) || "en".equals(language);
    }
}
