package ir.vigoapp.auth.service.login;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class ClientInfoTest {
    @Test
    void takesTheServletIpAndBoundsHeaderMetadataWithoutLogLineBreaks() {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr("198.51.100.24");
        request.addHeader("X-Forwarded-For", "203.0.113.99");
        request.addHeader("User-Agent", "Browser\r\nforged\u2028line" + "x".repeat(700));
        request.addHeader("X-Device-Id", "device\n" + "d".repeat(200));
        var client = ClientInfo.from(request);
        assertThat(client.ipAddress()).isEqualTo("198.51.100.24");
        assertThat(client.userAgent()).hasSize(512).doesNotContain("\r", "\n", "\u2028");
        assertThat(client.deviceId()).hasSize(128).doesNotContain("\n");
        assertThat(client.toString()).isEqualTo("ClientInfo[REDACTED]");
    }
}
