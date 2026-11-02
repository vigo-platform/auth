package ir.vigoapp.auth.config;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.util.LogbackMDCAdapter;
import ch.qos.logback.core.OutputStreamAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import net.logstash.logback.encoder.LogstashEncoder;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class StructuredLoggingTest {
    @Test
    void nativeFieldsAppearInJsonAndConsoleWhileTheMessageStaysSeparate() throws Exception {
        var context = new LoggerContext();
        context.setMDCAdapter(new LogbackMDCAdapter());
        try {
            var console = new ByteArrayOutputStream();
            var json = new ByteArrayOutputStream();
            var textEncoder = new PatternLayoutEncoder();
            textEncoder.setContext(context);
            textEncoder.setPattern("%kvp %msg%n");
            textEncoder.start();
            var jsonEncoder = new LogstashEncoder();
            jsonEncoder.setContext(context);
            jsonEncoder.start();
            var textAppender = new OutputStreamAppender<ILoggingEvent>();
            textAppender.setContext(context);
            textAppender.setEncoder(textEncoder);
            textAppender.setOutputStream(console);
            textAppender.start();
            var jsonAppender = new OutputStreamAppender<ILoggingEvent>();
            jsonAppender.setContext(context);
            jsonAppender.setEncoder(jsonEncoder);
            jsonAppender.setOutputStream(json);
            jsonAppender.start();
            var logger = context.getLogger("logging-test");
            logger.addAppender(textAppender);
            logger.addAppender(jsonAppender);
            logger.atInfo().addKeyValue("event", "refresh_rotated").addKeyValue("ip_address", "198.51.100.24")
                    .addKeyValue("user_id", 42).log("Refresh token rotated successfully.");

            var body = new ObjectMapper().readTree(json.toByteArray());
            assertThat(body.path("message").asText()).isEqualTo("Refresh token rotated successfully.");
            assertThat(body.path("event").asText()).isEqualTo("refresh_rotated");
            assertThat(body.path("ip_address").asText()).isEqualTo("198.51.100.24");
            assertThat(body.path("user_id").asInt()).isEqualTo(42);
            assertThat(console.toString(StandardCharsets.UTF_8)).contains("event=\"refresh_rotated\"",
                    "ip_address=\"198.51.100.24\"", "Refresh token rotated successfully.");
        } finally {
            context.stop();
        }
    }
}
