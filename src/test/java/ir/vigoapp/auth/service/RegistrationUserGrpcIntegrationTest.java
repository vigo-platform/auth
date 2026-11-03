package ir.vigoapp.auth.service;

import io.grpc.ManagedChannel;
import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.config.ApplicationProperties;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.config.AuthenticationConfig;
import ir.vigoapp.auth.config.UserGrpcConfig;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.registration.RegisterRequest;
import ir.vigoapp.auth.dto.registration.RegistrationInitiateRequest;
import ir.vigoapp.auth.dto.registration.RegistrationVerifyRequest;
import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ir.vigoapp.auth.dto.token.TokenResponse;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.repository.registration.RegistrationRepository;
import ir.vigoapp.auth.security.SecureTokens;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockMakers;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/** Requires a disposable stateful User mock and Redis; tests the actual RPC rather than a mocked client. */
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_USER_GRPC_PORT", matches = "[0-9]+")
class RegistrationUserGrpcIntegrationTest {
    private static final String PREFIX = "auth:registration:{registration}:";
    private final List<String> keys = new ArrayList<>();
    private final AtomicReference<String> deliveredCode = new AtomicReference<>();
    private LettuceConnectionFactory connections;
    private ManagedChannel channel;
    private StringRedisTemplate redis;
    private UserGrpcClient users;
    private SessionService sessions;
    private RegistrationService registration;
    private PasswordEncoder passwords;

    @BeforeEach
    void connect() {
        connections = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(System.getenv("AUTH_TEST_REDIS_PORT")));
        connections.afterPropertiesSet();
        connections.start();
        redis = new StringRedisTemplate(connections);
        var application = new ApplicationProperties();
        application.getUserGrpc().setHost("127.0.0.1");
        application.getUserGrpc().setPort(Integer.parseInt(System.getenv("AUTH_TEST_USER_GRPC_PORT")));
        var grpc = new UserGrpcConfig(application);
        channel = grpc.userGrpcChannel();
        users = new UserGrpcClient(grpc.userServiceStub(channel), application);
        var properties = new AuthProperties();
        properties.setOtpSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        var tokens = new SecureTokens(properties);
        var settings = new AuthSettingService(null, null) {
            @Override public AuthSettingDto getCurrent() {
                return AuthSettingDto.builder().registerEnabled(true).loginEnabled(true)
                        .emailNotificationEnabled(true).smsNotificationEnabled(true).build();
            }
        };
        var notifications = new NotificationService() {
            @Override public void sendRegistrationOtp(OtpChannel selected, String destination, String code) {
                deliveredCode.set(code);
            }
        };
        passwords = new AuthenticationConfig().passwordEncoder();
        sessions = mock(SessionService.class, withSettings().mockMaker(MockMakers.SUBCLASS));
        registration = new RegistrationService(new AuthPolicyService(settings),
                new AuthProtectionService(redis, properties, tokens), users, sessions, passwords,
                new RegistrationRepository(redis, properties), notifications, tokens, properties, Clock.systemUTC());
    }

    @AfterEach
    void disconnect() throws Exception {
        try {
            if (redis != null && !keys.isEmpty()) redis.delete(keys);
        } finally {
            if (channel != null) channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
            if (connections != null) connections.destroy();
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void verifiedRegistrationCreatesAnActiveAccountAndUsableCredentialsInTheRealUserMock(boolean email) {
        String suffix = UUID.randomUUID().toString().replace("-", "");
        String identifier = email ? "registration-" + suffix + "@example.com"
                : "+4477" + String.format(java.util.Locale.ROOT, "%09d", new java.security.SecureRandom().nextInt(1_000_000_000));
        var client = ClientInfo.builder().ipAddress("198.51.100.44").userAgent("registration-rpc-test").build();
        keys.addAll(List.of(PREFIX + "latest:" + identifier, "auth:otp-cooldown:identifier:" + identifier,
                "auth:failure:identifier:" + identifier, "auth:ip:" + client.ipAddress()));
        var initiated = registration.initiate(RegistrationInitiateRequest.builder().identifier(identifier).build(), client);
        keys.add(PREFIX + "challenge:" + initiated.mfaToken());
        assertThat(deliveredCode.get()).matches("[0-9]{6}");
        var verified = registration.verify(RegistrationVerifyRequest.builder()
                .mfaToken(initiated.mfaToken()).otp(deliveredCode.get()).build(), client);
        keys.add(PREFIX + "grant:" + verified.registrationToken());
        // Same completion fields and password as the reported failure, using a fresh test-only proof.
        var body = RegisterRequest.builder().registrationToken(verified.registrationToken())
                .password("example-password").firstName("Test").lastName("User").build();
        var tokens = new TokenResponse("Bearer", "access-token", 300, "refresh-token", 900);
        when(sessions.create(any(), eq(client))).thenReturn(tokens);
        var result = registration.complete(body, client);
        assertThat(result.userId()).isGreaterThan(3);
        assertThat(result.status()).isEqualTo(UserAccount.AccountStatus.ACTIVE);
        assertThat(result.tokens()).isSameAs(tokens);
        var account = users.getUserById(result.userId());
        verify(sessions).create(account, client);
        assertThat(account.emailVerified()).isEqualTo(email);
        assertThat(account.phoneVerified()).isEqualTo(!email);
        assertThat(account.credentialVersion()).isEqualTo(1);
        assertThat(account.credentialsExpired()).isFalse();
        var login = email ? users.getLoginInfoByEmail(identifier) : users.getLoginInfoByPhone(identifier);
        assertThat(login.user().userId()).isEqualTo(result.userId());
        assertThat(passwords.matches("example-password", login.passwordHash())).isTrue();
        assertThat(email ? users.checkEmailExists(identifier) : users.checkPhoneExists(identifier)).isTrue();
        assertThatThrownBy(() -> registration.complete(body, client)).isInstanceOfSatisfying(AuthException.class,
                error -> assertThat(error.getCode()).isEqualTo("INVALID_REGISTRATION_TOKEN"));
    }
}
