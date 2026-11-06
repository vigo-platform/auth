package ir.vigoapp.auth.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.kafka.core.KafkaOperations;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class NotificationServiceTest {
    private static final String TOPIC = "notification.commands";
    private static final String EMAIL = "user@example.com";
    private static final String OTP = "012345";
    private static final Instant NOW = Instant.parse("2026-11-07T00:00:00.123456789Z");
    private static final Instant EXPIRY = NOW.plusSeconds(47);

    private final KafkaOperations<String, byte[]> kafka = mock();
    private final ObjectMapper json = new ObjectMapper();
    private final NotificationService service = new NotificationService(kafka, json, Clock.fixed(NOW, ZoneOffset.UTC));
    private final OtpNotificationContext context = new OtpNotificationContext(UUID.randomUUID(), "en");

    @ParameterizedTest
    @CsvSource({
            "LOGIN_OTP,auth.login_otp.email.v1",
            "REGISTRATION_OTP,auth.registration_otp.email.v1",
            "PASSWORD_CHANGE_OTP,auth.password_change_otp.email.v1",
            "PASSWORD_RESET_OTP,auth.password_reset_otp.email.v1"
    })
    void publishesExactV1Command(String purpose, String template) throws Exception {
        when(kafka.send(eq(TOPIC), anyString(), any(byte[].class))).thenReturn(CompletableFuture.completedFuture(null));
        switch (purpose) {
            case "LOGIN_OTP" -> service.sendLoginOtp(OtpChannel.EMAIL, EMAIL, OTP, EXPIRY, context);
            case "REGISTRATION_OTP" -> service.sendRegistrationOtp(OtpChannel.EMAIL, EMAIL, OTP, EXPIRY, context);
            case "PASSWORD_CHANGE_OTP" -> service.sendPasswordChangeOtp(OtpChannel.EMAIL, EMAIL, OTP, EXPIRY, context);
            case "PASSWORD_RESET_OTP" -> service.sendPasswordResetOtp(OtpChannel.EMAIL, EMAIL, OTP, EXPIRY, context);
            default -> throw new AssertionError(purpose);
        }

        var key = ArgumentCaptor.forClass(String.class);
        var bytes = ArgumentCaptor.forClass(byte[].class);
        verify(kafka).send(eq(TOPIC), key.capture(), bytes.capture());
        assertThat(UUID.fromString(key.getValue()).version()).isEqualTo(4);
        assertThat(json.readTree(bytes.getValue())).isEqualTo(json.readTree("""
                {
                  "event_id": "%s",
                  "event_type": "NotificationRequested",
                  "event_version": 1,
                  "occurred_at": "2026-11-07T00:00:00.123456789Z",
                  "producer": "auth-service",
                  "correlation_id": "%s",
                  "data": {
                    "channel": "EMAIL",
                    "purpose": "%s",
                    "locale": "en",
                    "recipient": {"destination": "user@example.com"},
                    "template_id": "%s",
                    "template_parameters": {"otp_code": "012345"},
                    "expires_at": "2026-11-07T00:00:47.123Z"
                  }
                }
                """.formatted(key.getValue(), context.correlationId(), purpose, template)));
    }

    @Test
    void generatesANewEventIdForEachCommand() {
        when(kafka.send(eq(TOPIC), anyString(), any(byte[].class))).thenReturn(CompletableFuture.completedFuture(null));
        service.sendLoginOtp(OtpChannel.EMAIL, EMAIL, OTP, EXPIRY, context);
        service.sendLoginOtp(OtpChannel.EMAIL, EMAIL, OTP, EXPIRY, context);

        var key = ArgumentCaptor.forClass(String.class);
        verify(kafka, times(2)).send(eq(TOPIC), key.capture(), any(byte[].class));
        assertThat(key.getAllValues()).doesNotHaveDuplicates();
    }

    @Test
    void skipsNonEmailAndRejectsExpiredOrMalformedCommands() {
        service.sendLoginOtp(OtpChannel.SMS, "+989123456789", OTP, EXPIRY, context);
        service.sendPasswordChangeOtp(OtpChannel.IN_APP, "42", OTP, EXPIRY, context);

        assertThatThrownBy(() -> service.sendLoginOtp(OtpChannel.EMAIL, EMAIL, OTP, NOW, context))
                .isInstanceOf(AuthException.class);
        assertThatThrownBy(() -> service.sendLoginOtp(OtpChannel.EMAIL, EMAIL, "۰۱۲۳۴۵", EXPIRY, context))
                .isInstanceOf(AuthException.class);
        assertThatThrownBy(() -> service.sendLoginOtp(OtpChannel.EMAIL, "invalid..mail@example.com", OTP, EXPIRY, context))
                .isInstanceOf(AuthException.class);
        verifyNoInteractions(kafka);
    }

    @Test
    void surfacesBrokerFailureAsAnOtpDeliveryFailure() {
        when(kafka.send(eq(TOPIC), anyString(), any(byte[].class)))
                .thenReturn(CompletableFuture.failedFuture(new IllegalStateException("broker rejected send")));
        assertThatThrownBy(() -> service.sendRegistrationOtp(OtpChannel.EMAIL, EMAIL, OTP, EXPIRY, context))
                .isInstanceOfSatisfying(AuthException.class, exception -> {
                    assertThat(exception.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
                    assertThat(exception.getCode()).isEqualTo("OTP_DELIVERY_UNAVAILABLE");
                });
    }

    @Test
    void generatesAStableRequestIdAndUsesPersianForUnsupportedHeaders() {
        var request = new MockHttpServletRequest();
        request.addHeader("Accept-Language", "fr-CA");
        request.addHeader("X-Correlation-ID", "invalid");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        try {
            var first = OtpNotificationContext.current();
            assertThat(first.locale()).isEqualTo("fa");
            assertThat(first.correlationId().version()).isEqualTo(4);
            assertThat(OtpNotificationContext.current()).isEqualTo(first);
        } finally {
            RequestContextHolder.resetRequestAttributes();
        }
    }
}
