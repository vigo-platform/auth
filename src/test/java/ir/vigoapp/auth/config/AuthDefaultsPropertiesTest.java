package ir.vigoapp.auth.config;

import ir.vigoapp.auth.entity.OtpChannel;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class AuthDefaultsPropertiesTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class))
            .withUserConfiguration(ApplicationProperties.class)
            .withPropertyValues("app.user-grpc.host=localhost", "app.user-grpc.port=50051");

    @Test
    void bindsAllAuthDefaultsUnderStrictConfiguration() {
        runner.withPropertyValues(
                "app.auth-defaults.login-enabled=false",
                "app.auth-defaults.register-enabled=false",
                "app.auth-defaults.default-otp-channel=IN_APP",
                "app.auth-defaults.email-notification-enabled=true",
                "app.auth-defaults.sms-notification-enabled=true",
                "app.auth-defaults.in-app-notification-enabled=true"
        ).run(context -> {
            assertThat(context).hasNotFailed();
            var defaults = context.getBean(ApplicationProperties.class).getAuthDefaults();
            assertThat(defaults.isLoginEnabled()).isFalse();
            assertThat(defaults.isRegisterEnabled()).isFalse();
            assertThat(defaults.getDefaultOtpChannel()).isEqualTo(OtpChannel.IN_APP);
            assertThat(defaults.isEmailNotificationEnabled()).isTrue();
            assertThat(defaults.isSmsNotificationEnabled()).isTrue();
            assertThat(defaults.isInAppNotificationEnabled()).isTrue();
        });
    }

    @Test
    void rejectsUnsupportedOtpChannel() {
        runner.withPropertyValues("app.auth-defaults.default-otp-channel=UNKNOWN")
                .run(context -> assertThat(context).hasFailed());
    }
}
