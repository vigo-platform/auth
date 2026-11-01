package ir.vigoapp.auth.dto.setting;

import ir.vigoapp.auth.entity.AuthSetting;
import ir.vigoapp.auth.entity.OtpChannel;
import lombok.Builder;

import java.time.Instant;

/**
 * Immutable view of one auth settings revision, safe for caching and sharing.
 *
 * @version 1.0.0
 * @author logTAHA
 */
@Builder(toBuilder = true)
public record AuthSettingDto(
        long id,
        long version,
        Instant updatedAt,
        boolean loginEnabled,
        boolean registerEnabled,
        OtpChannel defaultOtpChannel,
        boolean emailNotificationEnabled,
        boolean smsNotificationEnabled,
        boolean inAppNotificationEnabled
) {
    public static AuthSettingDto from(AuthSetting setting) {
        return AuthSettingDto.builder()
                .id(setting.getId())
                .version(setting.getVersion())
                .updatedAt(setting.getUpdatedAt())
                .loginEnabled(setting.isLoginEnabled())
                .registerEnabled(setting.isRegisterEnabled())
                .defaultOtpChannel(setting.getDefaultOtpChannel())
                .emailNotificationEnabled(setting.isEmailNotificationEnabled())
                .smsNotificationEnabled(setting.isSmsNotificationEnabled())
                .inAppNotificationEnabled(setting.isInAppNotificationEnabled())
                .build();
    }
}
