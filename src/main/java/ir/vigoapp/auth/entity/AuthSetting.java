package ir.vigoapp.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

/**
 * Stores application-wide login, registration, OTP delivery, and notification settings.
 * Each change creates a new revision; the highest version is the active settings.
 *
 * @version 1.0.0
 * @author logTAHA
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "auth_settings", uniqueConstraints = @UniqueConstraint(name = "uk_auth_settings_version", columnNames = "version"))
public class AuthSetting {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Setter(AccessLevel.NONE)
    private Long id;

    /** Global revision number, assigned by the service when inserting a new settings row. */
    @Column(name = "version", nullable = false, updatable = false)
    @Setter(AccessLevel.NONE)
    private long version;

    /** Time of the latest insert or update performed by Hibernate. */
    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    @Setter(AccessLevel.NONE)
    private Instant updatedAt;

    @Column(name = "login_enabled", nullable = false)
    private boolean loginEnabled = true;

    @Column(name = "register_enabled", nullable = false)
    private boolean registerEnabled = true;

    @NotNull
    @Enumerated(EnumType.STRING)
    @Column(name = "default_otp_channel", nullable = false, length = 16)
    private OtpChannel defaultOtpChannel = OtpChannel.EMAIL;

    // Optional notifications are independent of authentication challenge delivery.
    @Column(name = "email_notification_enabled", nullable = false)
    private boolean emailNotificationEnabled;

    @Column(name = "sms_notification_enabled", nullable = false)
    private boolean smsNotificationEnabled;

    @Column(name = "in_app_notification_enabled", nullable = false)
    private boolean inAppNotificationEnabled;

    /** Builds a new revision while leaving identity and timestamps to Hibernate. */
    @Builder
    private AuthSetting(long version, boolean loginEnabled, boolean registerEnabled, OtpChannel defaultOtpChannel,
                        boolean emailNotificationEnabled, boolean smsNotificationEnabled,
                        boolean inAppNotificationEnabled) {
        this.version = version;
        this.loginEnabled = loginEnabled;
        this.registerEnabled = registerEnabled;
        this.defaultOtpChannel = defaultOtpChannel;
        this.emailNotificationEnabled = emailNotificationEnabled;
        this.smsNotificationEnabled = smsNotificationEnabled;
        this.inAppNotificationEnabled = inAppNotificationEnabled;
    }
}
