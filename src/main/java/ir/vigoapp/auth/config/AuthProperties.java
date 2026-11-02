package ir.vigoapp.auth.config;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "auth", ignoreUnknownFields = false)
public class AuthProperties {
    /** Base64 secret for audit-log identifier fingerprints only; not used by Redis or OTP verification. */
    @NotBlank
    private String otpSecret;

    private boolean passwordOtpRequired = false;

    @NotNull @DurationMin(seconds = 30)
    private Duration otpTtl = Duration.ofMinutes(5);
    @NotNull @DurationMin(seconds = 1)
    private Duration otpCooldown = Duration.ofMinutes(1);
    @Min(1) @Max(10)
    private int otpMaxAttempts = 3;
    @Min(1) @Max(100)
    private int maxFailedAttempts = 5;
    @NotNull @DurationMin(seconds = 1)
    private Duration failureWindow = Duration.ofMinutes(30);
    @NotNull @DurationMin(seconds = 1)
    private Duration lockDuration = Duration.ofMinutes(1);
    @NotNull @DurationMin(seconds = 1)
    private Duration maxLockDuration = Duration.ofMinutes(30);
    @Min(1)
    private int ipMaxRequests = 60;
    @NotNull @DurationMin(seconds = 1)
    private Duration ipWindow = Duration.ofMinutes(1);
    @NotNull @DurationMin(seconds = 1)
    private Duration refreshTokenTtl = Duration.ofDays(7);
    @NotNull @DurationMin(seconds = 1)
    private Duration sessionTtl = Duration.ofDays(30);
    @NotNull @DurationMin(seconds = 1)
    private Duration retention = Duration.ofDays(7);
    @NotNull @DurationMin(seconds = 1)
    private Duration cleanupInterval = Duration.ofHours(1);

    @AssertTrue(message = "lockDuration <= maxLockDuration <= failureWindow is required")
    public boolean isLockPolicyValid() {
        return lockDuration != null && maxLockDuration != null && failureWindow != null
                && lockDuration.compareTo(maxLockDuration) <= 0
                && maxLockDuration.compareTo(failureWindow) <= 0;
    }

    @AssertTrue(message = "refreshTokenTtl must not exceed sessionTtl")
    public boolean isRefreshPolicyValid() {
        return refreshTokenTtl != null && sessionTtl != null && refreshTokenTtl.compareTo(sessionTtl) <= 0;
    }
}
