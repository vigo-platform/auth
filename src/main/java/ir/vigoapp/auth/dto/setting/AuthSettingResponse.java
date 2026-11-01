package ir.vigoapp.auth.dto.setting;

import ir.vigoapp.auth.entity.OtpChannel;

/** Frontend settings view, excluding internal revision metadata. */
public record AuthSettingResponse(
        boolean loginEnabled,
        boolean registerEnabled,
        OtpChannel defaultOtpChannel,
        boolean emailNotificationEnabled,
        boolean smsNotificationEnabled,
        boolean inAppNotificationEnabled
) {
    public static AuthSettingResponse from(AuthSettingDto settings) {
        return new AuthSettingResponse(
                settings.loginEnabled(),
                settings.registerEnabled(),
                settings.defaultOtpChannel(),
                settings.emailNotificationEnabled(),
                settings.smsNotificationEnabled(),
                settings.inAppNotificationEnabled());
    }
}
