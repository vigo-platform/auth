package ir.vigoapp.auth.service;

import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChannel;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;

class AuthPolicyServiceTest {
    private AuthSettingDto current;
    private final AuthPolicyService policy = new AuthPolicyService(new AuthSettingService(null, null) {
        @Override public AuthSettingDto getCurrent() { return current; }
    });

    @ParameterizedTest
    @CsvSource({"false,false", "false,true", "true,false", "true,true"})
    void loginAndRegistrationSwitchesAreIndependent(boolean login, boolean register) {
        current = AuthSettingDto.builder().loginEnabled(login).registerEnabled(register).build();
        if (login) assertThat(policy.requireLoginEnabled()).isSameAs(current);
        else assertThatThrownBy(policy::requireLoginEnabled).isInstanceOfSatisfying(AuthException.class,
                error -> assertThat(error.getCode()).isEqualTo("LOGIN_DISABLED"));
        if (register) assertThatCode(policy::requireRegistrationEnabled).doesNotThrowAnyException();
        else assertThatThrownBy(policy::requireRegistrationEnabled).isInstanceOfSatisfying(AuthException.class,
                error -> assertThat(error.getCode()).isEqualTo("REGISTRATION_DISABLED"));
    }

    @ParameterizedTest
    @MethodSource("channelCombinations")
    void eachChannelUsesOnlyItsOwnSwitch(int switches, OtpChannel channel) {
        current = AuthSettingDto.builder().loginEnabled(true).defaultOtpChannel(channel)
                .emailNotificationEnabled((switches & 1) != 0)
                .smsNotificationEnabled((switches & 2) != 0)
                .inAppNotificationEnabled((switches & 4) != 0).build();
        boolean enabled = (switches & (1 << channel.ordinal())) != 0;
        if (enabled) {
            assertThatCode(() -> policy.requireLoginOtpEnabled(channel)).doesNotThrowAnyException();
            assertThat(policy.requireDefaultLoginOtpChannel()).isEqualTo(channel);
        } else {
            assertDisabled(() -> policy.requireLoginOtpEnabled(channel));
            assertDisabled(policy::requireDefaultLoginOtpChannel);
        }
    }

    @Test
    void everyCallUsesTheLatestSettingsAndNeverFallsBackFromADisabledDefault() {
        current = AuthSettingDto.builder().loginEnabled(true).defaultOtpChannel(OtpChannel.EMAIL)
                .emailNotificationEnabled(true).smsNotificationEnabled(true).build();
        assertThat(policy.requireDefaultLoginOtpChannel()).isEqualTo(OtpChannel.EMAIL);
        current = current.toBuilder().defaultOtpChannel(OtpChannel.SMS).build();
        assertThat(policy.requireDefaultLoginOtpChannel()).isEqualTo(OtpChannel.SMS);
        current = current.toBuilder().smsNotificationEnabled(false).build();
        assertDisabled(policy::requireDefaultLoginOtpChannel);
        current = current.toBuilder().defaultOtpChannel(null).build();
        assertDisabled(policy::requireDefaultLoginOtpChannel);
    }

    @Test
    void disablingLoginBlocksAllChannelsEvenIfTheirSwitchesAreOn() {
        current = AuthSettingDto.builder().loginEnabled(false).defaultOtpChannel(OtpChannel.EMAIL)
                .emailNotificationEnabled(true).smsNotificationEnabled(true).inAppNotificationEnabled(true).build();
        for (var channel : OtpChannel.values()) {
            assertThatThrownBy(() -> policy.requireLoginOtpEnabled(channel)).isInstanceOfSatisfying(AuthException.class,
                    error -> assertThat(error.getCode()).isEqualTo("LOGIN_DISABLED"));
        }
    }

    private static Stream<Object[]> channelCombinations() {
        return IntStream.range(0, 8).boxed().flatMap(switches -> Stream.of(OtpChannel.values())
                .map(channel -> new Object[]{switches, channel}));
    }

    private void assertDisabled(org.assertj.core.api.ThrowableAssert.ThrowingCallable operation) {
        assertThatThrownBy(operation).isInstanceOfSatisfying(AuthException.class, error -> {
            assertThat(error.getCode()).isEqualTo("OTP_CHANNEL_DISABLED");
            assertThat(error.getStatus().value()).isEqualTo(503);
        });
    }
}
