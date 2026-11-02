package ir.vigoapp.auth.dto;

import jakarta.servlet.http.HttpServletRequest;
import lombok.Builder;

@Builder
public record ClientInfo(String ipAddress, String userAgent, String deviceId) {
    public ClientInfo {
        ipAddress = limit(ipAddress, 64);
        userAgent = limit(userAgent, 512);
        deviceId = limit(deviceId, 128);
    }

    public static ClientInfo from(HttpServletRequest request) {
        // Forwarded headers are untrusted. A trusted ingress may configure the servlet remote address.
        return ClientInfo.builder()
                .ipAddress(request.getRemoteAddr())
                .userAgent(request.getHeader("User-Agent"))
                .deviceId(request.getHeader("X-Device-Id"))
                .build();
    }

    private static String limit(String value, int max) {
        return value == null ? null : value.substring(0, Math.min(value.length(), max))
                .replaceAll("[\\p{Cntrl}\\u2028\\u2029]", "_");
    }

    @Override
    public String toString() { return "ClientInfo[REDACTED]"; }
}
