package ir.vigoapp.auth.dto.setting;

import ir.vigoapp.auth.model.OtpChannel;
import lombok.Builder;

/** Frontend settings view, excluding internal revision metadata. */
@Builder
public record AuthSettingResponse(
        boolean loginEnabled,
        boolean registerEnabled,
        OtpChannel defaultOtpChannel,
        boolean emailNotificationEnabled,
        boolean smsNotificationEnabled,
        boolean inAppNotificationEnabled
) {
    public static AuthSettingResponse from(AuthSettingDto settings) {
        return AuthSettingResponse.builder()
                .loginEnabled(settings.loginEnabled())
                .registerEnabled(settings.registerEnabled())
                .defaultOtpChannel(settings.defaultOtpChannel())
                .emailNotificationEnabled(settings.emailNotificationEnabled())
                .smsNotificationEnabled(settings.smsNotificationEnabled())
                .inAppNotificationEnabled(settings.inAppNotificationEnabled())
                .build();
    }
}
