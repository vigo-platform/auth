package ir.vigoapp.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChannel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.core.KafkaOperations;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Slf4j
public class NotificationService {
    private static final String TOPIC = "notification.commands";
    private static final Pattern OTP_CODE = Pattern.compile("[0-9]{6}");
    private static final Pattern MAILBOX = Pattern.compile(
            "(?=.{1,64}@)[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*"
            + "@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            + "(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*");

    private final KafkaOperations<String, byte[]> kafka;
    private final ObjectMapper json;
    private final Clock clock;

    public void sendLoginOtp(OtpChannel channel, String destination, String code, Instant expiresAt,
                             OtpNotificationContext context) {
        send(Purpose.LOGIN_OTP, channel, destination, code, expiresAt, context);
    }

    public void sendRegistrationOtp(OtpChannel channel, String destination, String code, Instant expiresAt,
                                    OtpNotificationContext context) {
        send(Purpose.REGISTRATION_OTP, channel, destination, code, expiresAt, context);
    }

    public void sendPasswordChangeOtp(OtpChannel channel, String destination, String code, Instant expiresAt,
                                      OtpNotificationContext context) {
        send(Purpose.PASSWORD_CHANGE_OTP, channel, destination, code, expiresAt, context);
    }

    public void sendPasswordResetOtp(OtpChannel channel, String destination, String code, Instant expiresAt,
                                     OtpNotificationContext context) {
        send(Purpose.PASSWORD_RESET_OTP, channel, destination, code, expiresAt, context);
    }

    public void sendPasswordResetNotice(long userId) {
    }

    private void send(Purpose purpose, OtpChannel channel, String destination, String code, Instant expiresAt,
                      OtpNotificationContext context) {
        if (channel != OtpChannel.EMAIL) return;

        var occurredAt = clock.instant();
        var expiry = expiresAt.truncatedTo(ChronoUnit.MILLIS); // Redis stores challenge expiry in milliseconds.
        String eventId = UUID.randomUUID().toString();
        String mailbox = destination == null ? "" : destination.strip();
        if (mailbox.length() > 254 || !MAILBOX.matcher(mailbox).matches()) {
            throw deliveryFailed(purpose, eventId, context, "invalid_destination");
        }
        if (code == null || !OTP_CODE.matcher(code).matches() || !expiry.isAfter(occurredAt)) {
            throw deliveryFailed(purpose, eventId, context, "invalid_or_expired_otp");
        }

        var data = Map.of("channel", "EMAIL", "purpose", purpose.name(), "locale", context.locale(),
                "recipient", Map.of("destination", mailbox), "template_id", purpose.templateId,
                "template_parameters", Map.of("otp_code", code), "expires_at", expiry.toString());
        var event = Map.of("event_id", eventId, "event_type", "NotificationRequested", "event_version", 1,
                "occurred_at", occurredAt.toString(), "producer", "auth-service",
                "correlation_id", context.correlationId().toString(), "data", data);

        try {
            kafka.send(TOPIC, eventId, json.writeValueAsBytes(event)).get();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw deliveryFailed(purpose, eventId, context, "interrupted");
        } catch (JsonProcessingException | ExecutionException | RuntimeException exception) {
            var cause = exception instanceof ExecutionException ? exception.getCause() : exception;
            throw deliveryFailed(purpose, eventId, context, cause.getClass().getSimpleName());
        }
    }

    private static AuthException deliveryFailed(Purpose purpose, String eventId, OtpNotificationContext context, String reason) {
        log.atWarn().addKeyValue("event", "otp_publication_failed").addKeyValue("purpose", purpose)
                .addKeyValue("event_id", eventId).addKeyValue("correlation_id", context.correlationId())
                .addKeyValue("reason", reason).log("Email OTP command could not be published.");
        return new AuthException(HttpStatus.SERVICE_UNAVAILABLE, "OTP_DELIVERY_UNAVAILABLE",
                "Email verification is temporarily unavailable.", "ارسال کد تأیید ایمیل موقتاً در دسترس نیست.");
    }

    private enum Purpose {
        LOGIN_OTP("auth.login_otp.email.v1"),
        REGISTRATION_OTP("auth.registration_otp.email.v1"),
        PASSWORD_CHANGE_OTP("auth.password_change_otp.email.v1"),
        PASSWORD_RESET_OTP("auth.password_reset_otp.email.v1");

        private final String templateId;

        Purpose(String templateId) {
            this.templateId = templateId;
        }
    }
}
