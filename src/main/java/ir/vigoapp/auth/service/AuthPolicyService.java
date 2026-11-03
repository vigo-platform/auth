package ir.vigoapp.auth.service;

import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChannel;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

/** Runtime switches are owned by Auth, independently of the notification transport. */
@Service
@RequiredArgsConstructor
public class AuthPolicyService {
    private final AuthSettingService settings;

    public AuthSettingDto requireLoginEnabled() {
        var current = settings.getCurrent();
        if (!current.loginEnabled()) {
            throw new AuthException(HttpStatus.SERVICE_UNAVAILABLE, "LOGIN_DISABLED",
                    "Login is temporarily disabled.", "ورود موقتاً غیرفعال است.");
        }
        return current;
    }

    public void requireRegistrationEnabled() {
        requireRegistrationSettings();
    }

    public void requireRegistrationOtpEnabled(OtpChannel channel) {
        var current = requireRegistrationSettings();
        // A guest has no account or in-app destination yet.
        if (channel != OtpChannel.EMAIL && channel != OtpChannel.SMS) {
            throw new AuthException(HttpStatus.SERVICE_UNAVAILABLE, "OTP_CHANNEL_DISABLED",
                    "Registration requires email or SMS verification.", "تأیید ثبت‌نام باید از طریق ایمیل یا پیامک انجام شود.");
        }
        requireChannelEnabled(current, channel);
    }

    private AuthSettingDto requireRegistrationSettings() {
        var current = settings.getCurrent();
        if (!current.registerEnabled()) {
            throw new AuthException(HttpStatus.SERVICE_UNAVAILABLE, "REGISTRATION_DISABLED",
                    "Registration is temporarily disabled.", "ثبت‌نام موقتاً غیرفعال است.");
        }
        return current;
    }

    public void requireLoginOtpEnabled(OtpChannel channel) {
        requireChannelEnabled(requireLoginEnabled(), channel);
    }

    public OtpChannel requireDefaultLoginOtpChannel() {
        var current = requireLoginEnabled();
        var channel = current.defaultOtpChannel();
        requireChannelEnabled(current, channel);
        return channel;
    }

    private void requireChannelEnabled(AuthSettingDto current, OtpChannel channel) {
        boolean enabled = channel != null && switch (channel) {
            case EMAIL -> current.emailNotificationEnabled();
            case SMS -> current.smsNotificationEnabled();
            case IN_APP -> current.inAppNotificationEnabled();
        };
        if (!enabled) {
            throw new AuthException(HttpStatus.SERVICE_UNAVAILABLE, "OTP_CHANNEL_DISABLED",
                    "The requested verification channel is disabled.", "کانال تأیید درخواستی غیرفعال است.");
        }
    }
}
