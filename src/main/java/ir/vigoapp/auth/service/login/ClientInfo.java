package ir.vigoapp.auth.service.login;

import jakarta.servlet.http.HttpServletRequest;

public record ClientInfo(String ipAddress, String userAgent, String deviceId) {
    public ClientInfo {
        ipAddress = limit(ipAddress, 64);
        userAgent = limit(userAgent, 512);
        deviceId = limit(deviceId, 128);
    }

    public static ClientInfo from(HttpServletRequest request) {
        // Forwarded headers are untrusted. A trusted ingress may configure the servlet remote address.
        return new ClientInfo(request.getRemoteAddr(), request.getHeader("User-Agent"), request.getHeader("X-Device-Id"));
    }

    private static String limit(String value, int max) {
        return value == null ? null : value.substring(0, Math.min(value.length(), max))
                .replaceAll("[\\p{Cntrl}\\u2028\\u2029]", "_");
    }

    @Override
    public String toString() { return "ClientInfo[REDACTED]"; }
}
