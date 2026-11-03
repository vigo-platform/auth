package ir.vigoapp.auth.service;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.registration.RegisterRequest;
import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ir.vigoapp.auth.dto.token.TokenResponse;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.model.registration.RegistrationGrant;
import ir.vigoapp.auth.repository.registration.RegistrationRepository;
import ir.vigoapp.auth.security.SecureTokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class RegistrationServiceTest {
    private final UserGrpcClient users = classMock(UserGrpcClient.class);
    private final SessionService sessions = classMock(SessionService.class);
    private final AuthProtectionService protection = classMock(AuthProtectionService.class);
    private final RegistrationRepository repository = classMock(RegistrationRepository.class);
    private final PasswordEncoder passwords = mock(PasswordEncoder.class);
    private final ClientInfo client = ClientInfo.builder().ipAddress("127.0.0.1").build();
    private AuthSettingDto current;
    private RegistrationService registration;
    private RegistrationGrant grant;
    private RegisterRequest request;

    @BeforeEach
    void prepare() {
        current = AuthSettingDto.builder().registerEnabled(true).loginEnabled(true).emailNotificationEnabled(true).build();
        var policy = new AuthPolicyService(new AuthSettingService(null, null) {
            @Override public AuthSettingDto getCurrent() { return current; }
        });
        var properties = new AuthProperties();
        properties.setOtpSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        var tokens = new SecureTokens(properties);
        String token = tokens.randomToken();
        grant = grant(token, "OPEN");
        when(repository.findGrant(token)).thenReturn(Optional.of(grant));
        when(passwords.encode("new-password")).thenReturn("encoded-password");
        registration = new RegistrationService(policy, protection, users, sessions, passwords, repository,
                null, tokens, properties, Clock.systemUTC());
        request = RegisterRequest.builder().registrationToken(token).password("new-password").build();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void disablingRegistrationOrItsChannelDuringPasswordHashingPreventsRemoteAccountCreation(boolean registrationSwitch) {
        when(passwords.encode("new-password")).thenAnswer(invocation -> {
            current = registrationSwitch ? current.toBuilder().registerEnabled(false).build()
                    : current.toBuilder().emailNotificationEnabled(false).build();
            return "encoded-password";
        });
        assertThatThrownBy(() -> registration.complete(request, client))
                .isInstanceOfSatisfying(AuthException.class, error -> assertThat(error.getCode())
                        .isEqualTo(registrationSwitch ? "REGISTRATION_DISABLED" : "OTP_CHANNEL_DISABLED"));
        verify(passwords).encode("new-password");
        verifyNoInteractions(users, sessions);
        verify(repository, never()).claim(anyString(), anyString(), any());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void cleanupFailureCannotHideAConfirmedAccountCreation(boolean grantCleanupFailure) {
        when(repository.claim(anyString(), anyString(), any())).thenReturn(true);
        var created = activeAccount();
        when(users.createUser(any())).thenReturn(created);
        var tokens = new TokenResponse("Bearer", "access-token", 300, "refresh-token", 900);
        when(sessions.create(created, client)).thenReturn(tokens);
        if (grantCleanupFailure) doThrow(new IllegalStateException("test grant cleanup failure"))
                .when(repository).complete(anyString(), anyString());
        else doThrow(new IllegalStateException("test counter failure")).when(protection).clearFailures(any(), anyLong());

        var result = registration.complete(request, client);
        assertThat(result.userId()).isEqualTo(42);
        assertThat(result.status()).isEqualTo(UserAccount.AccountStatus.ACTIVE);
        assertThat(result.tokens()).isSameAs(tokens);
        verify(users, times(1)).createUser(any());
    }

    @Test
    void sessionCreationFailureDoesNotLetACompletedRegistrationCreateTheAccountAgain() {
        var created = activeAccount();
        when(repository.claim(anyString(), anyString(), any())).thenReturn(true);
        when(users.createUser(any())).thenReturn(created);
        when(repository.complete(eq(request.registrationToken()), anyString())).thenAnswer(invocation -> {
            when(repository.findGrant(request.registrationToken())).thenReturn(Optional.empty());
            return true;
        });
        var failure = new DataAccessResourceFailureException("test session storage failure");
        when(sessions.create(created, client)).thenThrow(failure);

        assertThatThrownBy(() -> registration.complete(request, client)).isSameAs(failure);
        assertThatThrownBy(() -> registration.complete(request, client)).isInstanceOfSatisfying(AuthException.class,
                error -> assertThat(error.getCode()).isEqualTo("INVALID_REGISTRATION_TOKEN"));
        verify(users).createUser(any());
        verify(sessions).create(created, client);
        verify(repository, never()).release(anyString(), anyString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"COMPLETED", "CLAIMED", "MISSING"})
    void losingAClaimRaceNeverReplaysACompletedRegistration(String state) {
        when(repository.findGrant(request.registrationToken())).thenReturn(Optional.of(grant),
                state.equals("MISSING") ? Optional.empty() : Optional.of(grant(request.registrationToken(), state)));
        when(repository.claim(anyString(), anyString(), any())).thenReturn(false);
        assertThatThrownBy(() -> registration.complete(request, client)).isInstanceOfSatisfying(AuthException.class,
                error -> assertThat(error.getCode()).isEqualTo(state.equals("CLAIMED")
                        ? "REGISTRATION_IN_PROGRESS" : "INVALID_REGISTRATION_TOKEN"));
        verifyNoInteractions(users);
    }

    @Test
    void anOldCompletedResultIsRejectedBeforePasswordHashingOrUserCreation() {
        when(repository.findGrant(request.registrationToken()))
                .thenReturn(Optional.of(grant(request.registrationToken(), "COMPLETED")));
        assertThatThrownBy(() -> registration.complete(request, client)).isInstanceOfSatisfying(AuthException.class,
                error -> assertThat(error.getCode()).isEqualTo("INVALID_REGISTRATION_TOKEN"));
        verifyNoInteractions(users, passwords);
    }

    @ParameterizedTest
    @CsvSource({"INVALID_ARGUMENT,INVALID_REQUEST", "ALREADY_EXISTS,ACCOUNT_ALREADY_EXISTS", "TIMEOUT,UserClientException"})
    void aValidCompletionRejectedByUserRecordsTheUpstreamReasonWithoutCredentials(UserClientException.Code code, String expected) {
        when(repository.claim(anyString(), anyString(), any())).thenReturn(true);
        doThrow(new UserClientException(code, "CreateUser")).when(users).createUser(any());
        var logger = (Logger) LoggerFactory.getLogger(RegistrationService.class);
        var logs = new ListAppender<ILoggingEvent>();
        logs.setContext(logger.getLoggerContext());
        logs.start();
        logger.addAppender(logs);
        try {
            assertThatThrownBy(() -> registration.complete(request, client)).satisfies(error -> {
                if (error instanceof AuthException auth) assertThat(auth.getCode()).isEqualTo(expected);
                else assertThat(error).isInstanceOf(UserClientException.class);
            });
            assertThat(logs.list).singleElement().satisfies(event -> {
                assertThat(event.getKeyValuePairs()).anySatisfy(pair -> {
                    assertThat(pair.key).isEqualTo("reason");
                    assertThat(pair.value).isEqualTo(code);
                }).anySatisfy(pair -> {
                    assertThat(pair.key).isEqualTo("operation");
                    assertThat(pair.value).isEqualTo("CreateUser");
                });
                assertThat(event.getFormattedMessage()).doesNotContain(request.password(), request.registrationToken());
                assertThat(event.getKeyValuePairs()).noneSatisfy(pair -> assertThat(List.of(request.password(),
                        request.registrationToken(), "encoded-password", grant.identifier())).contains(String.valueOf(pair.value)));
            });
        } finally {
            logger.detachAppender(logs);
            logs.stop();
        }
    }

    private RegistrationGrant grant(String token, String state) {
        return RegistrationGrant.builder().token(token).identifier("new@example.com").channel(OtpChannel.EMAIL)
                .state(state).expiresAt(Instant.now().plusSeconds(900)).build();
    }

    private UserAccount activeAccount() {
        return UserAccount.builder().userId(42).roles(List.of("USER")).email(grant.identifier())
                .status(UserAccount.AccountStatus.ACTIVE).emailVerified(true).credentialVersion(1).build();
    }

    private static <T> T classMock(Class<T> type) {
        return mock(type, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
    }
}
