package ir.vigoapp.auth.service;

import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.registration.RegisterRequest;
import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ir.vigoapp.auth.exception.AuthException;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class RegistrationServiceTest {
    @Test
    void disablingRegistrationDuringPasswordHashingPreventsRemoteAccountCreation() {
        var enabled = new AtomicBoolean(true);
        var policy = new AuthPolicyService(new AuthSettingService(null, null) {
            @Override public AuthSettingDto getCurrent() {
                return AuthSettingDto.builder().registerEnabled(enabled.get()).build();
            }
        });
        var users = mock(UserGrpcClient.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
        var protection = mock(LoginProtectionService.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
        var passwords = mock(PasswordEncoder.class);
        when(passwords.encode("new-password")).thenAnswer(invocation -> {
            enabled.set(false);
            return "encoded-password";
        });
        var registration = new RegistrationService(policy, protection, users, passwords);
        var request = RegisterRequest.builder().email("new@example.com").password("new-password").build();

        assertThatThrownBy(() -> registration.register(request, ClientInfo.builder().ipAddress("127.0.0.1").build()))
                .isInstanceOfSatisfying(AuthException.class,
                        error -> assertThat(error.getCode()).isEqualTo("REGISTRATION_DISABLED"));
        verify(passwords).encode("new-password");
        verifyNoInteractions(users);
    }
}
