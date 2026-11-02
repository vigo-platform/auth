package ir.vigoapp.auth.service;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.client.user.model.UserLoginInfo;
import ir.vigoapp.auth.client.user.model.CreateUserCommand;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.login.VerifyLoginRequest;
import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.repository.OtpChallengeRepository;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.repository.AuthSessionRepository;
import ir.vigoapp.auth.repository.RefreshTokenRepository;
import ir.vigoapp.auth.scheduling.AuthStateCleanup;
import ir.vigoapp.auth.security.SecureTokens;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Requires a disposable PostgreSQL database and Redis instance; never point these variables at application data. */
@EnabledIfEnvironmentVariable(named = "AUTH_TEST_DATABASE_URL", matches = ".+")
@SpringBootTest(properties = {
        "spring.datasource.url=${AUTH_TEST_DATABASE_URL}",
        "spring.datasource.username=postgres",
        "spring.datasource.password=${AUTH_TEST_DATABASE_PASSWORD}",
        "spring.data.redis.host=127.0.0.1",
        "spring.data.redis.port=${AUTH_TEST_REDIS_PORT}",
        "spring.data.redis.username=", "spring.data.redis.password=", "spring.data.redis.database=0",
        "auth.otp-secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "app.user-grpc.host=127.0.0.1", "app.user-grpc.port=50051"
})
@AutoConfigureMockMvc
@Import(LoginFlowIntegrationTest.TestDoubles.class)
class LoginFlowIntegrationTest {
    private static final ClientInfo CLIENT = new ClientInfo("127.0.0.1", "integration-test", "device-test");
    private static final String PASSWORD_HASH = new BCryptPasswordEncoder(4).encode("correct-password");
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired LoginService login;
    @Autowired SessionService sessions;
    @Autowired AuthStateCleanup cleanup;
    @Autowired AuthSessionRepository sessionRepository;
    @Autowired RefreshTokenRepository refreshRepository;
    @Autowired OtpChallengeRepository challenges;
    @Autowired SecureTokens tokens;
    @Autowired AuthProperties properties;
    @Autowired JwtDecoder decoder;
    @Autowired StringRedisTemplate redis;
    @Autowired javax.sql.DataSource dataSource;
    @Autowired UserGrpcClient users;
    @Autowired AuthSettingService settings;
    @Autowired NotificationService notifications;
    @Autowired Clock clock;
    @Autowired LoginProtectionService protection;
    @Autowired PasswordEncoder passwords;
    private final AtomicReference<Instant> now = new AtomicReference<>();
    private UserAccount user;
    private final Logger auditLogger = (Logger) LoggerFactory.getLogger("ir.vigoapp.auth");
    private ListAppender<ILoggingEvent> auditLogs;

    @AfterEach
    void detachAuditLogs() {
        if (auditLogs != null) {
            auditLogger.detachAppender(auditLogs);
            auditLogs.stop();
        }
    }

    @BeforeEach
    void resetState() {
        reset(users, settings, notifications, clock, protection);
        refreshRepository.deleteAllInBatch();
        sessionRepository.deleteAllInBatch();
        var keys = redis.keys("auth:*");
        if (keys != null && !keys.isEmpty()) redis.delete(keys);
        now.set(Instant.now());
        when(clock.instant()).thenAnswer(invocation -> now.get());
        properties.setPasswordOtpRequired(false);
        properties.setIpMaxRequests(60);
        properties.setMaxFailedAttempts(5);
        properties.setOtpMaxAttempts(3);
        properties.setOtpCooldown(Duration.ofMinutes(1));
        properties.setOtpTtl(Duration.ofMinutes(5));
        properties.setRefreshTokenTtl(Duration.ofDays(7));
        properties.setSessionTtl(Duration.ofDays(30));
        when(settings.getCurrent()).thenReturn(enabledSettings(OtpChannel.EMAIL));
        user = account(UserAccount.AccountStatus.ACTIVE, 3, false, true);
        doThrow(new UserClientException(UserClientException.Code.NOT_FOUND, "GetUserLoginInfoByEmail"))
                .when(users).getLoginInfoByEmail(anyString());
        doThrow(new UserClientException(UserClientException.Code.NOT_FOUND, "GetUserLoginInfoByPhone"))
                .when(users).getLoginInfoByPhone(anyString());
        setUser(user);
    }

    @Test
    void passwordLoginIssuesBothTokensInTheProjectEnvelopeAndStoresOnlyHashes() throws Exception {
        var result = password("USER@EXAMPLE.COM", "correct-password");
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        var root = tree(result);
        assertThat(root.path("success").asBoolean()).isTrue();
        assertThat(root.has("messageFa")).isTrue();
        assertThat(root.has("code")).isFalse();
        assertThat(root.path("data").path("step").asText()).isEqualTo("SUCCESS");
        assertThat(result.getResponse().getHeader("Cache-Control")).isEqualTo("no-store");
        var pair = root.path("data").path("tokens");
        var jwt = decoder.decode(pair.path("accessToken").asText());
        assertThat(jwt.getSubject()).isEqualTo("42");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("USER");
        assertThat(refreshRepository.findAll()).singleElement().satisfies(token ->
                assertThat(token.getTokenHash()).isEqualTo(tokens.hash(pair.path("refreshToken").asText())));
        verifyNoInteractions(notifications);
    }

    @Test
    void disablingLoginBlocksEveryNewLoginPathBeforeAnyExternalWork() throws Exception {
        when(settings.getCurrent()).thenReturn(enabledSettings(OtpChannel.EMAIL).toBuilder().loginEnabled(false).build());
        for (var request : Map.of(
                "/login-password", Map.of("identifier", "user@example.com", "password", "correct-password"),
                "/login-otp-email", Map.of("email", "user@example.com"),
                "/login-otp-phone", Map.of("phone", "09123456789"),
                "/verify", Map.of("mfaToken", tokens.randomToken(), "otp", "123456")).entrySet()) {
            var response = call(request.getKey(), request.getValue());
            assertThat(response.getResponse().getStatus()).isEqualTo(503);
            assertThat(tree(response).path("code").asText()).isEqualTo("LOGIN_DISABLED");
        }
        verifyNoInteractions(users, notifications, protection);
        assertThat(sessionRepository.count()).isZero();
    }

    @ParameterizedTest
    @CsvSource({"/login-otp-email,email,user@example.com,EMAIL", "/login-otp-email,email,missing@example.com,EMAIL",
            "/login-otp-phone,phone,09123456789,SMS", "/login-otp-phone,phone,09111111111,SMS"})
    void disabledExplicitChannelRejectsKnownAndUnknownAccountsBeforeCooldownOrLookup(
            String path, String fieldName, String identifier, OtpChannel channel) throws Exception {
        when(settings.getCurrent()).thenReturn(disableChannel(enabledSettings(OtpChannel.EMAIL), channel));
        var response = call(path, Map.of(fieldName, identifier));
        assertThat(response.getResponse().getStatus()).isEqualTo(503);
        assertThat(tree(response).path("code").asText()).isEqualTo("OTP_CHANNEL_DISABLED");
        verifyNoInteractions(users, notifications, protection);
        assertThat(redis.keys("auth:*")).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({"EMAIL,true", "SMS,true", "IN_APP,true", "EMAIL,false", "SMS,false", "IN_APP,false"})
    void disabledDefaultNeverBypassesAccountOrGlobalSecondFactor(OtpChannel channel, boolean enrolled) throws Exception {
        if (enrolled) setUser(twoFactorAccount());
        else properties.setPasswordOtpRequired(true);
        when(settings.getCurrent()).thenReturn(disableChannel(enabledSettings(channel), channel));
        var response = password("user@example.com", "correct-password");
        assertThat(response.getResponse().getStatus()).isEqualTo(503);
        assertThat(tree(response).path("code").asText()).isEqualTo("OTP_CHANNEL_DISABLED");
        verifyNoInteractions(notifications);
        assertThat(redis.keys("auth:otp:{login}:challenge:*")).isEmpty();
        assertThat(sessionRepository.count()).isZero();
    }

    @ParameterizedTest
    @EnumSource(OtpChannel.class)
    void disablingAnIssuedChallengesChannelBlocksVerificationWithoutUsingAnAttempt(OtpChannel channel) throws Exception {
        setUser(twoFactorAccount());
        var active = enabledSettings(channel);
        when(settings.getCurrent()).thenReturn(active);
        var started = tree(password("user@example.com", "correct-password"));
        String token = started.at("/data/challenge/mfaToken").asText();
        var challenge = challenges.find(token).orElseThrow();
        when(settings.getCurrent()).thenReturn(disableChannel(active, channel));
        var response = verifyOtp(token, challenge.code());
        assertThat(response.getResponse().getStatus()).isEqualTo(503);
        assertThat(tree(response).path("code").asText()).isEqualTo("OTP_CHANNEL_DISABLED");
        assertThat(challenges.find(token).orElseThrow()).satisfies(stored -> {
            assertThat(stored.state()).isEqualTo("OPEN");
            assertThat(stored.failedAttempts()).isZero();
        });
        verify(users, never()).getUserById(anyLong());
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void changingDefaultDoesNotInvalidateAnEnabledIssuedChannelOrOverrideExplicitEndpoints() throws Exception {
        var challenge = startOtp();
        when(settings.getCurrent()).thenReturn(enabledSettings(OtpChannel.SMS));
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(200);
        clearCooldown();
        var next = tree(call("/login-otp-email", Map.of("email", "user@example.com")));
        assertThat(next.at("/data/challenge/channel").asText()).isEqualTo("EMAIL");
    }

    @Test
    void allChannelsCanBeDisabledWhilePasswordOnlyLoginRemainsAvailable() throws Exception {
        when(settings.getCurrent()).thenReturn(enabledSettings(OtpChannel.EMAIL).toBuilder()
                .emailNotificationEnabled(false).smsNotificationEnabled(false).inAppNotificationEnabled(false).build());
        assertThat(password("user@example.com", "correct-password").getResponse().getStatus()).isEqualTo(200);
        assertThat(sessionRepository.count()).isEqualTo(1);
        verifyNoInteractions(notifications);
    }

    @Test
    void disablingLoginDuringPasswordLookupCannotIssueTokens() throws Exception {
        doAnswer(invocation -> {
            when(settings.getCurrent()).thenReturn(enabledSettings(OtpChannel.EMAIL).toBuilder().loginEnabled(false).build());
            return new UserLoginInfo(user, PASSWORD_HASH);
        }).when(users).getLoginInfoByEmail("user@example.com");
        assertThat(tree(password("user@example.com", "correct-password")).path("code").asText()).isEqualTo("LOGIN_DISABLED");
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void disablingChannelDuringOtpLookupCannotCreateOrSendAChallenge() throws Exception {
        doAnswer(invocation -> {
            when(settings.getCurrent()).thenReturn(disableChannel(enabledSettings(OtpChannel.EMAIL), OtpChannel.EMAIL));
            return new UserLoginInfo(user, PASSWORD_HASH);
        }).when(users).getLoginInfoByEmail("user@example.com");
        var response = call("/login-otp-email", Map.of("email", "user@example.com"));
        assertThat(tree(response).path("code").asText()).isEqualTo("OTP_CHANNEL_DISABLED");
        assertThat(redis.keys("auth:otp:{login}:challenge:*")).isEmpty();
        verifyNoInteractions(notifications);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void disablingLoginOrChannelDuringVerificationCannotIssueTokens(boolean disableLogin) throws Exception {
        var challenge = startOtp();
        doAnswer(invocation -> {
            var changed = enabledSettings(OtpChannel.EMAIL);
            when(settings.getCurrent()).thenReturn(disableLogin ? changed.toBuilder().loginEnabled(false).build()
                    : disableChannel(changed, OtpChannel.EMAIL));
            return user;
        }).when(users).getUserById(42);
        var response = verifyOtp(challenge.token(), challenge.code());
        assertThat(response.getResponse().getStatus()).isEqualTo(503);
        assertThat(tree(response).path("code").asText()).isEqualTo(disableLogin ? "LOGIN_DISABLED" : "OTP_CHANNEL_DISABLED");
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void existingSessionsCanRefreshAndLogoutWhileLoginRegistrationAndChannelsAreDisabled() throws Exception {
        var pair = createSession();
        when(settings.getCurrent()).thenReturn(AuthSettingDto.builder().defaultOtpChannel(OtpChannel.EMAIL).build());
        var response = call("/refresh", Map.of("refreshToken", pair.refreshToken()));
        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        String replacement = tree(response).at("/data/refreshToken").asText();
        assertThat(call("/logout", Map.of("refreshToken", replacement)).getResponse().getStatus()).isEqualTo(200);
        assertAllFamiliesRevoked();
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void registrationDisabledPreventsCreationRegardlessOfLoginSetting(boolean loginEnabled) throws Exception {
        when(settings.getCurrent()).thenReturn(enabledSettings(OtpChannel.EMAIL).toBuilder()
                .loginEnabled(loginEnabled).registerEnabled(false).build());
        var response = call("/register", Map.of("email", "new@example.com", "password", "new-password"));
        assertThat(response.getResponse().getStatus()).isEqualTo(503);
        assertThat(tree(response).path("code").asText()).isEqualTo("REGISTRATION_DISABLED");
        verifyNoInteractions(users, notifications, protection);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void registrationNormalizesContactsHashesPasswordAndDoesNotAutoLogin(boolean loginEnabled) throws Exception {
        captureAuditLogs();
        when(settings.getCurrent()).thenReturn(enabledSettings(OtpChannel.EMAIL).toBuilder().loginEnabled(loginEnabled).build());
        var created = user.toBuilder().email("new@example.com").phone("09111111111")
                .status(UserAccount.AccountStatus.PENDING_VERIFICATION).emailVerified(false).phoneVerified(false).build();
        doReturn(created).when(users).createUser(any());
        var response = call("/register", Map.of("email", " NEW@EXAMPLE.COM ", "phone", "00989111111111",
                "password", "new-password", "firstName", "Test", "lastName", "User"));
        assertThat(response.getResponse().getStatus()).isEqualTo(201);
        assertThat(response.getResponse().getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(tree(response).at("/data/userId").asLong()).isEqualTo(42);
        assertThat(tree(response).at("/data/status").asText()).isEqualTo("PENDING_VERIFICATION");
        var command = ArgumentCaptor.forClass(CreateUserCommand.class);
        verify(users).createUser(command.capture());
        assertThat(command.getValue()).satisfies(value -> {
            assertThat(value.email()).isEqualTo("new@example.com");
            assertThat(value.phone()).isEqualTo("+989111111111");
            assertThat(value.firstName()).isEqualTo("Test");
            assertThat(value.lastName()).isEqualTo("User");
            assertThat(value.passwordHash()).isNotEqualTo("new-password");
            assertThat(passwords.matches("new-password", value.passwordHash())).isTrue();
        });
        assertThat(sessionRepository.count()).isZero();
        verifyNoInteractions(notifications);
        assertNoCredentialLogs("new-password", command.getValue().passwordHash(), "new@example.com");
    }

    @ParameterizedTest
    @CsvSource({"email,new@example.com", "phone,09111111111"})
    void registrationSupportsOneContactWithoutRequiringTheOther(String fieldName, String value) throws Exception {
        var created = user.toBuilder().email(fieldName.equals("email") ? "new@example.com" : null)
                .phone(fieldName.equals("phone") ? "+989111111111" : null).build();
        doReturn(created).when(users).createUser(any());
        assertThat(call("/register", Map.of(fieldName, value, "password", "new-password"))
                .getResponse().getStatus()).isEqualTo(201);
    }

    @ParameterizedTest
    @ValueSource(strings = {"{}", "{\"email\":\"new@example.com\",\"password\":\"short\"}",
            "{\"password\":\"new-password\"}", "{\"email\":\"09111111111\",\"password\":\"new-password\"}",
            "{\"phone\":\"new@example.com\",\"password\":\"new-password\"}",
            "{\"email\":\" \",\"password\":\"new-password\"}"})
    void invalidRegistrationCannotCreateAnAccountOrExposeThePassword(String body) throws Exception {
        var result = mvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest()).andReturn();
        assertThat(result.getResponse().getContentAsString()).doesNotContain("new-password", "short");
        verifyNoInteractions(users, notifications);
    }

    @Test
    void registrationRejectsOversizedUtf8PasswordsRatherThanTruncatingThem() throws Exception {
        var result = call("/register", Map.of("email", "new@example.com", "password", "پ".repeat(37)));
        assertThat(result.getResponse().getStatus()).isEqualTo(400);
        assertThat(tree(result).path("code").asText()).isEqualTo("INVALID_PASSWORD_LENGTH");
        verifyNoInteractions(users);
    }

    @ParameterizedTest
    @CsvSource({"ALREADY_EXISTS,409,ACCOUNT_ALREADY_EXISTS", "INVALID_ARGUMENT,400,INVALID_REQUEST",
            "TIMEOUT,503,AUTH_SERVICE_UNAVAILABLE", "UNAVAILABLE,503,AUTH_SERVICE_UNAVAILABLE"})
    void registrationMapsUserServiceErrorsWithoutExposingCredentials(UserClientException.Code code, int status, String error) throws Exception {
        doThrow(new UserClientException(code, "CreateUser")).when(users).createUser(any());
        var response = call("/register", Map.of("email", "new@example.com", "password", "new-password"));
        assertThat(response.getResponse().getStatus()).isEqualTo(status);
        assertThat(tree(response).path("code").asText()).isEqualTo(error);
        assertThat(response.getResponse().getContentAsString()).doesNotContain("new-password");
    }

    @Test
    void registrationRejectsAnUpstreamResponseWithADifferentIdentity() throws Exception {
        doReturn(user).when(users).createUser(any());
        var response = call("/register", Map.of("email", "new@example.com", "password", "new-password"));
        assertThat(response.getResponse().getStatus()).isEqualTo(503);
        assertThat(tree(response).path("code").asText()).isEqualTo("AUTH_SERVICE_UNAVAILABLE");
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void registrationUsesTheExistingIpLimit() throws Exception {
        properties.setIpMaxRequests(1);
        protection.checkIp(CLIENT);
        var response = call("/register", Map.of("email", "new@example.com", "password", "new-password"));
        assertThat(response.getResponse().getStatus()).isEqualTo(429);
        assertThat(tree(response).path("code").asText()).isEqualTo("RATE_LIMITED");
        verifyNoInteractions(users);
    }

    @Test
    void wrongPasswordAndUnknownAccountHaveTheSameErrorAndAttemptsEventuallyLock() throws Exception {
        var unknown = tree(password("missing@example.com", "wrong-password"));
        var wrong = tree(password("user@example.com", "wrong-password"));
        assertThat(unknown.path("code").asText()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(unknown.path("message")).isEqualTo(wrong.path("message"));
        for (int i = 1; i < 5; i++) assertThat(password("user@example.com", "wrong-password").getResponse().getStatus()).isEqualTo(401);
        var locked = password("user@example.com", "correct-password");
        assertThat(locked.getResponse().getStatus()).isEqualTo(429);
        assertThat(tree(locked).path("code").asText()).isEqualTo("LOGIN_TEMPORARILY_LOCKED");
        assertThat(Long.parseLong(locked.getResponse().getHeader("Retry-After"))).isPositive();
        assertThat(refreshRepository.count()).isZero();
    }

    @Test
    void lockAppliesToTheAccountAcrossEmailAndPhoneAliases() throws Exception {
        for (int i = 0; i < 5; i++) password("user@example.com", "wrong-password");
        assertThat(password("09123456789", "correct-password").getResponse().getStatus()).isEqualTo(429);
    }

    @Test
    void unknownOtpAccountReceivesTheSameResponseWithoutSendingANotification() throws Exception {
        var unknown = tree(call("/login-otp-email", Map.of("email", "missing@example.com")));
        verifyNoInteractions(notifications);
        var known = tree(call("/login-otp-email", Map.of("email", "user@example.com")));
        assertThat(unknown.path("message")).isEqualTo(known.path("message"));
        assertThat(unknown.at("/data/challenge/mfaToken").asText()).matches("[A-Za-z0-9_-]{43}");
        assertThat(known.at("/data/challenge/mfaToken").asText()).matches("[A-Za-z0-9_-]{43}");
        verify(notifications).sendLoginOtp(eq(42L), eq(OtpChannel.EMAIL), eq("user@example.com"), matches("[0-9]{6}"));
    }

    @Test
    void phoneOtpUsesSmsAndCanonicalPhone() throws Exception {
        var result = call("/login-otp-phone", Map.of("phone", "09123456789"));
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        verify(users).getLoginInfoByPhone("+989123456789");
        verify(notifications).sendLoginOtp(eq(42L), eq(OtpChannel.SMS), eq("+989123456789"), anyString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"09111111111", "+989111111111", "00989111111111", "9111111111"})
    void localPhoneFromUserCreatesAVerifiableRedisOtpAndSharesTheCanonicalCooldown(String input) throws Exception {
        var localUser = user.toBuilder().phone("09111111111").build();
        doReturn(new UserLoginInfo(localUser, PASSWORD_HASH)).when(users).getLoginInfoByPhone("+989111111111");
        doReturn(localUser).when(users).getUserById(42);

        var response = call("/login-otp-phone", Map.of("phone", input));
        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        String token = tree(response).at("/data/challenge/mfaToken").asText();
        var stored = challenges.find(token).orElseThrow();
        assertThat(stored.destination()).isEqualTo("09111111111");
        assertThat(stored.identifierKey()).isEqualTo("identifier:+989111111111");
        assertThat(stored.code()).matches("[0-9]{6}");
        verify(notifications).sendLoginOtp(42L, OtpChannel.SMS, "09111111111", stored.code());

        var resend = call("/login-otp-phone", Map.of("phone", "+989111111111"));
        assertThat(resend.getResponse().getStatus()).isEqualTo(429);
        assertThat(tree(resend).path("code").asText()).isEqualTo("OTP_COOLDOWN");
        assertThat(verifyOtp(token, stored.code()).getResponse().getStatus()).isEqualTo(200);
        assertThat(sessionRepository.count()).isEqualTo(1);
    }

    @Test
    void passwordPhoneLoginAcceptsTheEquivalentLocalPhoneReturnedByUser() throws Exception {
        var localUser = user.toBuilder().phone("09111111111").build();
        doReturn(new UserLoginInfo(localUser, PASSWORD_HASH)).when(users).getLoginInfoByPhone("+989111111111");

        var response = password("09111111111", "correct-password");

        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        assertThat(tree(response).at("/data/step").asText()).isEqualTo("SUCCESS");
        assertThat(sessionRepository.count()).isEqualTo(1);
    }

    @Test
    void phoneLookupStillRejectsAnAccountWithADifferentPhone() throws Exception {
        var wrongUser = user.toBuilder().phone("09111111112").build();
        doReturn(new UserLoginInfo(wrongUser, PASSWORD_HASH)).when(users).getLoginInfoByPhone("+989111111111");

        var response = call("/login-otp-phone", Map.of("phone", "09111111111"));

        assertThat(response.getResponse().getStatus()).isEqualTo(503);
        assertThat(redis.keys("auth:otp:{login}:challenge:*")).isEmpty();
        verifyNoInteractions(notifications);
    }

    @Test
    void otpCanBeUsedOnlyOnceAndStoresReadableValuesInRedis() throws Exception {
        var challenge = startOtp();
        var result = verifyOtp(challenge.token(), challenge.code());
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(401);
        assertThat(refreshRepository.count()).isEqualTo(1);
        var stored = challenges.find(challenge.token()).orElseThrow();
        assertThat(stored.code()).isEqualTo(challenge.code());
        assertThat(stored.token()).isEqualTo(challenge.token());
        assertThat(stored.state()).isEqualTo("CLOSED");
    }

    @Test
    void redisKeysAndOtpValuesAreReadableAndNamespaced() throws Exception {
        var challenge = startOtp();
        String challengeKey = "auth:otp:{login}:challenge:" + challenge.token();
        assertThat(redis.keys("auth:*")).containsExactlyInAnyOrder(
                "auth:ip:127.0.0.1", "auth:otp-cooldown:identifier:user@example.com",
                "auth:otp-cooldown:account:42", "auth:otp:{login}:latest:account:42", challengeKey);
        assertThat(redis.opsForValue().get("auth:otp:{login}:latest:account:42")).isEqualTo(challengeKey);
        assertThat(redis.<String, String>opsForHash().entries(challengeKey))
                .containsEntry("identifierKey", "identifier:user@example.com")
                .containsEntry("destination", "user@example.com")
                .containsEntry("userId", "42").containsEntry("credentialVersion", "3")
                .containsEntry("code", challenge.code()).containsEntry("channel", "EMAIL")
                .containsEntry("passwordVerified", "false")
                .doesNotContainKeys("codeHash", "destinationKey", "tokenHash");
        assertThat(challenges.find(challenge.token()).orElseThrow().toString()).doesNotContain(challenge.code(), challenge.token());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void thirdWrongOtpDeletesTheChallengeAndEvenTheCorrectCodeThenFails(boolean twoFactorEnabled) throws Exception {
        if (twoFactorEnabled) setUser(twoFactorAccount());
        var challenge = twoFactorEnabled ? startPasswordOtp() : startOtp();
        String wrong = challenge.code().equals("000000") ? "000001" : "000000";
        for (int i = 1; i <= 2; i++) {
            assertThat(verifyOtp(challenge.token(), wrong).getResponse().getStatus()).isEqualTo(401);
            var stored = challenges.find(challenge.token()).orElseThrow();
            assertThat(stored.failedAttempts()).isEqualTo(i);
            assertThat(stored.state()).isEqualTo("OPEN");
        }
        assertThat(verifyOtp(challenge.token(), wrong).getResponse().getStatus()).isEqualTo(401);
        assertThat(challenges.find(challenge.token())).isEmpty();
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void concurrentWrongCodesAtomicallyDeleteTheChallengeAtThreeAttempts() throws Exception {
        var challenge = startOtp();
        String wrong = challenge.code().equals("000000") ? "000001" : "000000";
        verifyOtp(challenge.token(), wrong);
        var results = race(() -> {
            login.verify(new VerifyLoginRequest(challenge.token(), wrong), CLIENT);
            return "SUCCESS";
        });
        assertThat(results).containsOnly("INVALID_OTP");
        assertThat(challenges.find(challenge.token())).isEmpty();
        assertThat(sessionRepository.count()).isZero();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void expiredOtpCannotIssueTokens(boolean twoFactorEnabled) throws Exception {
        if (twoFactorEnabled) setUser(twoFactorAccount());
        var challenge = twoFactorEnabled ? startPasswordOtp() : startOtp();
        now.updateAndGet(value -> value.plus(Duration.ofMinutes(6)));
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(401);
        assertThat(refreshRepository.count()).isZero();
    }

    @Test
    void cooldownBlocksResendAndResendInvalidatesThePreviousChallenge() throws Exception {
        var first = startOtp();
        var cooldown = call("/login-otp-email", Map.of("email", "user@example.com"));
        assertThat(cooldown.getResponse().getStatus()).isEqualTo(429);
        assertThat(tree(cooldown).path("code").asText()).isEqualTo("OTP_COOLDOWN");
        clearCooldown();
        var second = startOtp();
        assertThat(verifyOtp(first.token(), first.code()).getResponse().getStatus()).isEqualTo(401);
        assertThat(verifyOtp(second.token(), second.code()).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void accountCooldownReportsRemainingTimeInsteadOfTheFullConfiguredDuration() throws Exception {
        properties.setPasswordOtpRequired(true);
        assertThat(password("09123456789", "correct-password").getResponse().getStatus()).isEqualTo(200);
        String key = "auth:otp-cooldown:account:42";
        redis.expire(key, Duration.ofMillis(5500));
        long beforeMs = redis.getExpire(key, TimeUnit.MILLISECONDS);

        var result = password("user@example.com", "correct-password");
        long afterMs = redis.getExpire(key, TimeUnit.MILLISECONDS);
        assertThat(result.getResponse().getStatus()).isEqualTo(429);
        assertThat(tree(result).path("code").asText()).isEqualTo("OTP_COOLDOWN");
        long retryAfter = Long.parseLong(result.getResponse().getHeader("Retry-After"));
        assertThat(retryAfter).isBetween(Math.max(1, (afterMs + 999) / 1000), (beforeMs + 999) / 1000);
        assertThat(tree(result).at("/data/retryAfterSeconds").asLong()).isEqualTo(retryAfter);
        assertThat(afterMs).isPositive().isLessThanOrEqualTo(beforeMs);
        verify(notifications, times(1)).sendLoginOtp(eq(42L), eq(OtpChannel.EMAIL), anyString(), anyString());
        assertThat(redis.keys("auth:otp:{login}:challenge:*")).hasSize(1);
    }

    @ParameterizedTest
    @CsvSource({"1, 1", "999, 1", "1000, 1", "1001, 2", "1500, 2", "5000, 5"})
    void accountCooldownRetryAfterRoundsRemainingMillisecondsUp(long remainingMs, long seconds) throws Exception {
        properties.setPasswordOtpRequired(true);
        doReturn(remainingMs).when(protection).reserveAccountCooldown(42L);

        var result = password("user@example.com", "correct-password");
        assertThat(result.getResponse().getStatus()).isEqualTo(429);
        assertThat(result.getResponse().getHeader("Retry-After")).isEqualTo(Long.toString(seconds));
        assertThat(tree(result).at("/data/retryAfterSeconds").asLong()).isEqualTo(seconds);
        verifyNoInteractions(notifications);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void concurrentOtpVerificationHasOnlyOneWinner(boolean twoFactorEnabled) throws Exception {
        if (twoFactorEnabled) setUser(twoFactorAccount());
        var challenge = twoFactorEnabled ? startPasswordOtp() : startOtp();
        var results = race(() -> {
            login.verify(new VerifyLoginRequest(challenge.token(), challenge.code()), CLIENT);
            return "SUCCESS";
        });
        assertThat(results).containsExactlyInAnyOrder("SUCCESS", "INVALID_OTP");
        assertThat(refreshRepository.count()).isEqualTo(1);
    }

    @Test
    void passwordCanRequireOtpAndNoTokensExistBeforeVerification() throws Exception {
        properties.setPasswordOtpRequired(true);
        var result = tree(password("user@example.com", "correct-password"));
        assertThat(result.at("/data/step").asText()).isEqualTo("OTP_REQUIRED");
        assertThat(refreshRepository.count()).isZero();
        var code = ArgumentCaptor.forClass(String.class);
        verify(notifications).sendLoginOtp(eq(42L), eq(OtpChannel.EMAIL), eq("user@example.com"), code.capture());
        assertThat(verifyOtp(result.at("/data/challenge/mfaToken").asText(), code.getValue()).getResponse().getStatus()).isEqualTo(200);
    }

    @ParameterizedTest
    @CsvSource({
            "false, false, user@example.com", "false, true, user@example.com",
            "true, false, user@example.com", "true, true, user@example.com",
            "false, false, 09123456789", "false, true, 09123456789",
            "true, false, 09123456789", "true, true, 09123456789"
    })
    void passwordLoginCombinesAccountEnrollmentAndGlobalPolicy(boolean enabled, boolean global, String identifier) throws Exception {
        captureAuditLogs();
        if (enabled) setUser(twoFactorAccount());
        properties.setPasswordOtpRequired(global);
        var response = password(identifier, "correct-password");
        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        var result = tree(response);
        if (!enabled && !global) {
            assertThat(result.at("/data/step").asText()).isEqualTo("SUCCESS");
            assertThat(sessionRepository.count()).isEqualTo(1);
            verifyNoInteractions(notifications);
            return;
        }

        assertThat(result.at("/data/step").asText()).isEqualTo("OTP_REQUIRED");
        assertThat(result.at("/data/tokens").isMissingNode()).isTrue();
        assertThat(sessionRepository.count()).isZero();
        assertThat(refreshRepository.count()).isZero();
        var code = ArgumentCaptor.forClass(String.class);
        verify(notifications).sendLoginOtp(eq(42L), eq(OtpChannel.EMAIL), eq("user@example.com"), code.capture());
        String token = result.at("/data/challenge/mfaToken").asText();
        assertThat(challenges.find(token).orElseThrow().passwordVerified()).isTrue();
        assertThat(redis.opsForHash().get("auth:otp:{login}:challenge:" + token, "passwordVerified")).isEqualTo("true");
        var required = auditEvent("login_second_factor_required");
        assertThat(field(required, "two_factor_enabled")).isEqualTo(enabled);
        assertThat(field(required, "password_otp_required")).isEqualTo(global);
        assertThat(field(required, "auth_method")).isEqualTo("PASSWORD_OTP");
        assertThat(field(required, "ip_address")).isEqualTo("127.0.0.1");
        assertThat(field(auditEvent("otp_challenge_created"), "auth_method")).isEqualTo("PASSWORD_OTP");
        assertThat(auditLogs.list).noneMatch(event -> "login_success".equals(field(event, "event")));

        String wrong = code.getValue().equals("000000") ? "000001" : "000000";
        assertThat(verifyOtp(token, wrong).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.count()).isZero();
        assertThat(field(auditEvent("otp_verification_failed"), "auth_method")).isEqualTo("PASSWORD_OTP");
        assertThat(verifyOtp(token, code.getValue()).getResponse().getStatus()).isEqualTo(200);
        assertThat(sessionRepository.count()).isEqualTo(1);
        assertThat(refreshRepository.count()).isEqualTo(1);
        assertThat(field(auditEvent("login_success"), "auth_method")).isEqualTo("PASSWORD_OTP");
        assertThat(verifyOtp(token, code.getValue()).getResponse().getStatus()).isEqualTo(401);
        assertNoCredentialLogs("correct-password", PASSWORD_HASH, "user@example.com", user.phone(), token, code.getValue(), wrong);
    }

    @ParameterizedTest
    @EnumSource(OtpChannel.class)
    void accountTwoFactorUsesTheConfiguredVerifiedChannel(OtpChannel channel) throws Exception {
        setUser(twoFactorAccount());
        when(settings.getCurrent()).thenReturn(enabledSettings(channel));
        var result = tree(password("user@example.com", "correct-password"));
        assertThat(result.at("/data/step").asText()).isEqualTo("OTP_REQUIRED");
        assertThat(result.at("/data/challenge/channel").asText()).isEqualTo(channel.name());
        String destination = switch (channel) {
            case EMAIL -> user.email();
            case SMS -> user.phone();
            case IN_APP -> "42";
        };
        var code = ArgumentCaptor.forClass(String.class);
        verify(notifications).sendLoginOtp(eq(42L), eq(channel), eq(destination), code.capture());
        assertThat(verifyOtp(result.at("/data/challenge/mfaToken").asText(), code.getValue()).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void twoFactorDoesNotIssueAChallengeForAnIncorrectPassword() throws Exception {
        setUser(twoFactorAccount());
        assertThat(password("user@example.com", "wrong-password").getResponse().getStatus()).isEqualTo(401);
        assertThat(redis.keys("auth:otp:{login}:challenge:*")).isEmpty();
        assertThat(sessionRepository.count()).isZero();
        verifyNoInteractions(notifications);
    }

    @ParameterizedTest
    @EnumSource(value = OtpChannel.class, names = {"EMAIL", "SMS"})
    void twoFactorCannotFallBackToPasswordOnlyWhenTheChannelIsUnverified(OtpChannel channel) throws Exception {
        captureAuditLogs();
        setUser(user.toBuilder().emailVerified(false).phoneVerified(false).twoFactorEnabled(true).build());
        when(settings.getCurrent()).thenReturn(enabledSettings(channel));
        var response = password("user@example.com", "correct-password");
        assertThat(response.getResponse().getStatus()).isEqualTo(401);
        assertThat(tree(response).path("code").asText()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(field(auditEvent("login_rejected"), "reason")).isEqualTo("otp_channel_unavailable");
        assertThat(sessionRepository.count()).isZero();
        assertThat(redis.keys("auth:otp:{login}:challenge:*")).isEmpty();
        verifyNoInteractions(notifications);
    }

    @ParameterizedTest
    @CsvSource({"/login-otp-email, email, user@example.com, EMAIL", "/login-otp-phone, phone, 09123456789, SMS"})
    void passwordlessOtpCannotBypassTwoFactorAndDoesNotRevealEnrollment(String path, String fieldName, String identifier, String channel) throws Exception {
        captureAuditLogs();
        setUser(twoFactorAccount());
        var response = call(path, Map.of(fieldName, identifier));
        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        var result = tree(response);
        assertThat(result.at("/data/step").asText()).isEqualTo("OTP_REQUIRED");
        assertThat(result.at("/data/challenge/channel").asText()).isEqualTo(channel);
        String token = result.at("/data/challenge/mfaToken").asText();
        assertThat(token).matches("[A-Za-z0-9_-]{43}");
        assertThat(challenges.find(token)).isEmpty();
        assertThat(verifyOtp(token, "012345").getResponse().getStatus()).isEqualTo(401);
        assertThat(field(auditEvent("otp_request_accepted"), "reason")).isEqualTo("password_verification_required");
        assertThat(sessionRepository.count()).isZero();
        verifyNoInteractions(notifications);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void enablingTwoFactorInvalidatesOutstandingPasswordlessAndLegacyChallenges(boolean legacy) throws Exception {
        captureAuditLogs();
        var challenge = startOtp();
        if (legacy) redis.opsForHash().delete("auth:otp:{login}:challenge:" + challenge.token(), "passwordVerified");
        assertThat(challenges.find(challenge.token()).orElseThrow().passwordVerified()).isFalse();
        setUser(twoFactorAccount());

        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(401);
        assertThat(field(auditEvent("otp_rejected"), "reason")).isEqualTo("password_verification_required");
        assertThat(challenges.find(challenge.token()).orElseThrow().state()).isEqualTo("CLOSED");
        assertThat(sessionRepository.count()).isZero();
        assertThat(refreshRepository.count()).isZero();
        assertNoCredentialLogs(challenge.token(), challenge.code(), PASSWORD_HASH, user.email());
    }

    @Test
    void legacyPasswordlessChallengeStillWorksForAnAccountWithoutTwoFactor() throws Exception {
        var challenge = startOtp();
        redis.opsForHash().delete("auth:otp:{login}:challenge:" + challenge.token(), "passwordVerified");
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(200);
        assertThat(sessionRepository.count()).isEqualTo(1);
    }

    @Test
    void eachRefreshTokenKeepsItsIssuingClientInfoAcrossRotations() {
        var first = createSession();
        var session = sessionRepository.findAll().getFirst();
        var nextClient = new ClientInfo("203.0.113.10", "next-browser", "next-device");
        var next = sessions.refresh(first.refreshToken(), nextClient);
        var lastClient = new ClientInfo("2001:db8::1", null, null);
        var last = sessions.refresh(next.refreshToken(), lastClient);

        assertThat(refreshRepository.findByTokenHash(tokens.hash(first.refreshToken())).orElseThrow())
                .satisfies(token -> {
                    assertThat(token.getIpAddress()).isEqualTo(CLIENT.ipAddress());
                    assertThat(token.getUserAgent()).isEqualTo(CLIENT.userAgent());
                    assertThat(token.getDeviceId()).isEqualTo(CLIENT.deviceId());
                    assertThat(token.getConsumedAt()).isNotNull();
                    assertThat(token.isActive()).isFalse();
                });
        assertThat(refreshRepository.findByTokenHash(tokens.hash(next.refreshToken())).orElseThrow())
                .satisfies(token -> {
                    assertThat(token.getIpAddress()).isEqualTo(nextClient.ipAddress());
                    assertThat(token.getUserAgent()).isEqualTo(nextClient.userAgent());
                    assertThat(token.getDeviceId()).isEqualTo(nextClient.deviceId());
                    assertThat(token.getConsumedAt()).isNotNull();
                    assertThat(token.isActive()).isFalse();
                });
        assertThat(refreshRepository.findByTokenHash(tokens.hash(last.refreshToken())).orElseThrow())
                .satisfies(token -> {
                    assertThat(token.getIpAddress()).isEqualTo(lastClient.ipAddress());
                    assertThat(token.getUserAgent()).isNull();
                    assertThat(token.getDeviceId()).isNull();
                    assertThat(token.getConsumedAt()).isNull();
                    assertThat(token.isActive()).isTrue();
                });
        assertThat(refreshRepository.findAll()).hasSize(3)
                .allSatisfy(token -> assertThat(token.getSession().getId()).isEqualTo(session.getId()));
        assertThat(sessionRepository.findAll()).singleElement()
                .usingRecursiveComparison().isEqualTo(session);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void passwordAndOtpLoginStoreTheIssuingRequestMetadataOnTheRefreshToken(boolean otp) throws Exception {
        String path;
        Map<String, String> body;
        if (otp) {
            var challenge = startOtp();
            path = "/verify";
            body = Map.of("mfaToken", challenge.token(), "otp", challenge.code());
        } else {
            path = "/login-password";
            body = Map.of("identifier", "user@example.com", "password", "correct-password");
        }
        mvc.perform(post("/api/v1/auth" + path).with(request -> {
                    request.setRemoteAddr("203.0.113.20");
                    return request;
                }).header("User-Agent", "issuing-browser").header("X-Device-Id", "issuing-device")
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.step").value("SUCCESS"));

        assertThat(refreshRepository.findAll()).singleElement().satisfies(token -> {
            assertThat(token.getIpAddress()).isEqualTo("203.0.113.20");
            assertThat(token.getUserAgent()).isEqualTo("issuing-browser");
            assertThat(token.getDeviceId()).isEqualTo("issuing-device");
        });
    }

    @Test
    void rotationConsumesOldTokenAndReuseCommitsFamilyRevocation() throws Exception {
        var pair = createSession();
        var rotated = call("/refresh", Map.of("refreshToken", pair.refreshToken()));
        assertThat(rotated.getResponse().getStatus()).isEqualTo(200);
        var next = tree(rotated).path("data");
        assertThat(next.path("refreshToken").asText()).isNotEqualTo(pair.refreshToken());
        assertThat(refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow().getConsumedAt()).isNotNull();
        assertThat(refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow().isActive()).isFalse();
        assertThat(refreshRepository.findByTokenHash(tokens.hash(next.path("refreshToken").asText())).orElseThrow().isActive()).isTrue();
        assertThat(call("/refresh", Map.of("refreshToken", pair.refreshToken())).getResponse().getStatus()).isEqualTo(401);
        assertThat(call("/refresh", Map.of("refreshToken", next.path("refreshToken").asText())).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.findAll().getFirst().getRevokedReason()).isEqualTo("REFRESH_REUSE");
        assertAllFamiliesRevoked();
        assertThat(sessions.isAccessSessionActive(decoder.decode(next.path("accessToken").asText()))).isFalse();
    }

    @Test
    void concurrentRefreshCannotForkTheTokenFamily() throws Exception {
        var pair = createSession();
        var results = race(() -> {
            sessions.refresh(pair.refreshToken(), CLIENT);
            return "SUCCESS";
        });
        assertThat(results).containsExactlyInAnyOrder("SUCCESS", "INVALID_REFRESH_TOKEN");
        assertThat(refreshRepository.count()).isEqualTo(2);
        assertThat(sessionRepository.findAll().getFirst().getRevokedReason()).isEqualTo("REFRESH_REUSE");
        assertAllFamiliesRevoked();
    }

    @Test
    void logoutUsingAnAncestorRevokesItsDescendantAndAccessTokens() throws Exception {
        var pair = createSession();
        var next = sessions.refresh(pair.refreshToken(), CLIENT);
        assertThat(call("/logout", Map.of("refreshToken", pair.refreshToken())).getResponse().getStatus()).isEqualTo(200);
        assertThat(call("/logout", Map.of("refreshToken", pair.refreshToken())).getResponse().getStatus()).isEqualTo(200);
        assertThat(call("/refresh", Map.of("refreshToken", next.refreshToken())).getResponse().getStatus()).isEqualTo(401);
        assertAllFamiliesRevoked();
        mvc.perform(post("/api/v1/auth/logout-all").header("Authorization", "Bearer " + next.accessToken()))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void logoutAllRequiresAccessAuthenticationAndRevokesAllSessions() throws Exception {
        mvc.perform(post("/api/v1/auth/logout-all")).andExpect(status().isUnauthorized());
        var first = createSession();
        var second = createSession();
        mvc.perform(post("/api/v1/auth/logout-all").header("Authorization", "Bearer " + first.accessToken()))
                .andExpect(status().isOk());
        assertThat(sessionRepository.findAll()).allSatisfy(session -> assertThat(session.getRevokedAt()).isNotNull());
        assertThat(sessions.isAccessSessionActive(decoder.decode(second.accessToken()))).isFalse();
        assertAllFamiliesRevoked();
    }

    @Test
    void credentialChangeRevokesAllOutdatedSessionsOnRefresh() throws Exception {
        var first = createSession();
        createSession();
        doReturn(account(UserAccount.AccountStatus.ACTIVE, 4, false, true)).when(users).getUserById(42);
        assertThat(call("/refresh", Map.of("refreshToken", first.refreshToken())).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.findAll()).allSatisfy(session -> assertThat(session.getRevokedReason()).isEqualTo("USER_STATE_CHANGED"));
        assertAllFamiliesRevoked();
    }

    @Test
    void oldCredentialRefreshPreservesNewSessionsAndOtherUsers() throws Exception {
        var oldest = sessions.create(account(UserAccount.AccountStatus.ACTIVE, 2, false, true), CLIENT);
        var old = createSession();
        var rotatedOld = sessions.refresh(old.refreshToken(), CLIENT);
        var currentUser = account(UserAccount.AccountStatus.ACTIVE, 4, false, true);
        setUser(currentUser);
        var current = sessions.create(currentUser, CLIENT);
        var otherUser = user.toBuilder().userId(43).build();
        doReturn(otherUser).when(users).getUserById(43);
        var other = sessions.create(otherUser, CLIENT);

        assertThat(call("/refresh", Map.of("refreshToken", rotatedOld.refreshToken()))
                .getResponse().getStatus()).isEqualTo(401);

        assertThat(sessionRepository.findAll())
                .filteredOn(session -> session.getUserId() == 42 && session.getCredentialVersion() < 4)
                .hasSize(2).allSatisfy(session -> {
                    assertThat(session.isRevoked()).isTrue();
                    assertThat(session.getRevokedReason()).isEqualTo("USER_STATE_CHANGED");
                });
        for (var pair : List.of(oldest, old, rotatedOld)) {
            var token = refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow();
            assertThat(token.isActive()).isFalse();
            assertThat(token.getRevokedAt()).isNotNull();
            assertThat(sessions.isAccessSessionActive(decoder.decode(pair.accessToken()))).isFalse();
        }
        assertThat(refreshRepository.findByTokenHash(tokens.hash(old.refreshToken())).orElseThrow()
                .getConsumedAt()).isNotNull();
        for (var pair : List.of(current, other)) {
            var token = refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow();
            assertThat(token.isActive()).isTrue();
            assertThat(token.getRevokedAt()).isNull();
            assertThat(sessions.isAccessSessionActive(decoder.decode(pair.accessToken()))).isTrue();
            assertThat(call("/refresh", Map.of("refreshToken", pair.refreshToken()))
                    .getResponse().getStatus()).isEqualTo(200);
        }
    }

    @Test
    void oldCredentialRefreshPreservesSessionsNewerThanTheUserSnapshot() throws Exception {
        var old = createSession();
        var snapshot = account(UserAccount.AccountStatus.ACTIVE, 4, false, true);
        setUser(snapshot);
        var current = sessions.create(snapshot, CLIENT);
        var newer = sessions.create(snapshot.toBuilder().credentialVersion(5).build(), CLIENT);

        assertThat(call("/refresh", Map.of("refreshToken", old.refreshToken()))
                .getResponse().getStatus()).isEqualTo(401);

        // A newer password change/login may commit after the User lookup took its snapshot.
        for (var pair : List.of(current, newer)) {
            var token = refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow();
            assertThat(token.isActive()).isTrue();
            assertThat(token.getRevokedAt()).isNull();
            assertThat(sessions.isAccessSessionActive(decoder.decode(pair.accessToken()))).isTrue();
        }
    }

    @ParameterizedTest
    @CsvSource({"SUSPENDED, false", "ACTIVE, true"})
    void ineligibleAccountStillRevokesAllCredentialVersions(UserAccount.AccountStatus status, boolean expired)
            throws Exception {
        var old = createSession();
        var current = sessions.create(account(UserAccount.AccountStatus.ACTIVE, 4, false, true), CLIENT);
        setUser(account(status, 4, expired, true));

        assertThat(call("/refresh", Map.of("refreshToken", old.refreshToken()))
                .getResponse().getStatus()).isEqualTo(401);

        assertAllFamiliesRevoked();
        assertThat(sessions.isAccessSessionActive(decoder.decode(current.accessToken()))).isFalse();
    }

    @Test
    void userServiceFailureDoesNotConsumeRefreshTokenAndRetryCanSucceed() throws Exception {
        var first = createSession();
        doThrow(new UserClientException(UserClientException.Code.TIMEOUT, "GetUserById")).when(users).getUserById(42);
        var result = call("/refresh", Map.of("refreshToken", first.refreshToken()));
        assertThat(result.getResponse().getStatus()).isEqualTo(503);
        assertThat(refreshRepository.findAll().getFirst().getConsumedAt()).isNull();
        assertThat(refreshRepository.findAll().getFirst().isActive()).isTrue();
        doReturn(user).when(users).getUserById(42);
        assertThat(call("/refresh", Map.of("refreshToken", first.refreshToken())).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void failedRotationRollsBackDeactivationOfTheOriginalToken() {
        var first = createSession();
        // Make the replacement violate the database's strict expiry constraint.
        properties.setRefreshTokenTtl(Duration.ZERO);
        try {
            assertThatThrownBy(() -> sessions.refresh(first.refreshToken(), CLIENT))
                    .isInstanceOf(org.springframework.dao.DataAccessException.class);
        } finally {
            properties.setRefreshTokenTtl(Duration.ofDays(7));
        }

        var original = refreshRepository.findByTokenHash(tokens.hash(first.refreshToken())).orElseThrow();
        assertThat(original.isActive()).isTrue();
        assertThat(original.getConsumedAt()).isNull();
        assertThat(original.getRevokedAt()).isNull();
        assertThat(refreshRepository.count()).isEqualTo(1);
        sessions.refresh(first.refreshToken(), CLIENT);
        assertThat(refreshRepository.findById(original.getId()).orElseThrow().isActive()).isFalse();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void userServiceFailureDoesNotConsumeCorrectOtp(boolean twoFactorEnabled) throws Exception {
        var current = twoFactorEnabled ? twoFactorAccount() : user;
        setUser(current);
        var challenge = twoFactorEnabled ? startPasswordOtp() : startOtp();
        doThrow(new UserClientException(UserClientException.Code.UNAVAILABLE, "GetUserById")).when(users).getUserById(42);
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(503);
        assertThat(challenges.find(challenge.token()).orElseThrow().state()).isEqualTo("OPEN");
        assertThat(challenges.find(challenge.token()).orElseThrow().passwordVerified()).isEqualTo(twoFactorEnabled);
        doReturn(current).when(users).getUserById(42);
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void cleanupRevokesExpiredFamiliesWithoutDeletingHistoryAndIsIdempotent() {
        now.updateAndGet(value -> value.truncatedTo(java.time.temporal.ChronoUnit.MICROS));
        properties.setRetention(Duration.ofDays(7));
        var first = createSession();
        sessions.refresh(first.refreshToken(), CLIENT);
        var loggedOut = createSession();
        sessions.logout(loggedOut.refreshToken(), CLIENT);
        var originalTokens = refreshRepository.findAll();
        var consumedAt = originalTokens.stream().filter(t -> t.getConsumedAt() != null)
                .findFirst().orElseThrow().getConsumedAt();
        var logoutTime = sessionRepository.findAll().stream().filter(s -> s.getRevokedAt() != null)
                .findFirst().orElseThrow().getRevokedAt();

        // At the exact boundary, the strict cutoff must leave these families untouched.
        now.updateAndGet(value -> value.plus(Duration.ofDays(37)));
        cleanup.cleanup();
        assertThat(refreshRepository.findAll()).filteredOn(t -> t.getRevokedAt() == null).hasSize(2)
                .allSatisfy(t -> assertThat(t.getRevokedAt()).isNull());
        now.updateAndGet(value -> value.plusSeconds(1));
        var active = createSession();
        var revokedAt = now.get();
        cleanup.cleanup();
        assertThat(sessionRepository.count()).isEqualTo(3);
        assertThat(sessionRepository.findAll()).filteredOn(s -> s.isRevoked()).hasSize(2);
        assertThat(refreshRepository.count()).isEqualTo(4);
        assertThat(sessionRepository.findAll()).filteredOn(s -> s.getRevokedReason() != null)
                .extracting(s -> s.getRevokedReason()).containsExactlyInAnyOrder("LOGOUT", "EXPIRED_CLEANUP");
        assertThat(sessionRepository.findAll()).filteredOn(s -> "LOGOUT".equals(s.getRevokedReason()))
                .allSatisfy(s -> assertThat(s.getRevokedAt()).isEqualTo(logoutTime));
        assertThat(refreshRepository.findAll()).filteredOn(t -> t.getRevokedAt() != null).hasSize(3)
                .allSatisfy(t -> assertThat(t.getRevokedAt()).isEqualTo(
                        t.getTokenHash().equals(tokens.hash(loggedOut.refreshToken())) ? logoutTime : revokedAt));
        assertThat(refreshRepository.findAll()).filteredOn(t -> t.getConsumedAt() != null)
                .singleElement().satisfies(t -> assertThat(t.getConsumedAt()).isEqualTo(consumedAt));
        assertThatThrownBy(() -> sessions.refresh(first.refreshToken(), CLIENT)).isInstanceOf(AuthException.class);
        sessions.refresh(active.refreshToken(), CLIENT);
        now.updateAndGet(value -> value.plusSeconds(1));
        cleanup.cleanup();
        assertThat(sessionRepository.count()).isEqualTo(3);
        assertThat(sessionRepository.findAll()).filteredOn(s -> s.isRevoked()).hasSize(2);
        assertThat(refreshRepository.count()).isEqualTo(5);
        assertThat(refreshRepository.findAll()).filteredOn(t -> t.getRevokedAt() != null).hasSize(3)
                .allSatisfy(t -> assertThat(t.getRevokedAt()).isEqualTo(
                        t.getTokenHash().equals(tokens.hash(loggedOut.refreshToken())) ? logoutTime : revokedAt));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void eitherSessionRevocationSignalRejectsAccessAndRefresh(boolean flagOnly) throws Exception {
        var pair = createSession();
        var sessionId = refreshRepository.findSessionIdByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow();
        setRevocationState("auth_sessions", sessionId, flagOnly);
        assertThat(sessions.isAccessSessionActive(decoder.decode(pair.accessToken()))).isFalse();
        mvc.perform(post("/api/v1/auth/logout-all").header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isUnauthorized());
        clearInvocations(users);
        assertThatThrownBy(() -> sessions.refresh(pair.refreshToken(), CLIENT)).isInstanceOf(AuthException.class);
        verify(users, never()).getUserById(anyLong());
        assertAllFamiliesRevoked();
        assertThat(refreshRepository.count()).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void eitherRefreshRevocationSignalRejectsWithoutConsumingOrIssuing(boolean flagOnly) throws Exception {
        var pair = createSession();
        var token = refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow();
        setRevocationState("refresh_tokens", token.getId(), flagOnly);
        clearInvocations(users);
        assertThatThrownBy(() -> sessions.refresh(pair.refreshToken(), CLIENT)).isInstanceOf(AuthException.class);
        verify(users, never()).getUserById(anyLong());
        assertThat(refreshRepository.findById(token.getId()).orElseThrow().getConsumedAt()).isNull();
        assertThat(refreshRepository.findById(token.getId()).orElseThrow().isActive()).isFalse();
        assertThat(refreshRepository.count()).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"TOKEN_EXPIRED", "SESSION_EXPIRED", "SESSION_FLAG", "SESSION_TIMESTAMP",
            "CONSUMED", "TOKEN_TIMESTAMP"})
    void backgroundTaskDeactivatesUnusableTokensWithoutARefreshRequest(String reason) throws Exception {
        var pair = createSession();
        var token = refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow();
        var session = sessionRepository.findAll().getFirst();
        switch (reason) {
            case "TOKEN_EXPIRED" -> now.set(token.getExpiresAt());
            case "SESSION_EXPIRED" -> now.set(session.getExpiresAt());
            case "SESSION_FLAG" -> setRevocationState("auth_sessions", session.getId(), true);
            case "SESSION_TIMESTAMP" -> setRevocationState("auth_sessions", session.getId(), false);
            case "TOKEN_TIMESTAMP" -> setRevocationState("refresh_tokens", token.getId(), false);
            case "CONSUMED" -> {
                try (var connection = dataSource.getConnection();
                     var statement = connection.prepareStatement("UPDATE refresh_tokens SET consumed_at = ? WHERE id = ?")) {
                    statement.setTimestamp(1, java.sql.Timestamp.from(now.get()));
                    statement.setObject(2, token.getId());
                    assertThat(statement.executeUpdate()).isEqualTo(1);
                }
            }
            default -> throw new AssertionError(reason);
        }
        // The stored flag is intentionally stale until the task reconciles it.
        assertThat(refreshRepository.findById(token.getId()).orElseThrow().isActive()).isTrue();
        var control = createSession();

        cleanup.deactivateUnusableRefreshTokens();
        var inactive = refreshRepository.findById(token.getId()).orElseThrow();
        assertThat(inactive.isActive()).isFalse();
        assertThat(refreshRepository.findByTokenHash(tokens.hash(control.refreshToken())).orElseThrow().isActive()).isTrue();
        cleanup.deactivateUnusableRefreshTokens();
        var repeated = refreshRepository.findById(token.getId()).orElseThrow();
        assertThat(repeated.isActive()).isFalse();
        assertThat(repeated.getConsumedAt()).isEqualTo(inactive.getConsumedAt());
        assertThat(repeated.getRevokedAt()).isEqualTo(inactive.getRevokedAt());
        assertThat(refreshRepository.count()).isEqualTo(2);
        if (reason.equals("TOKEN_EXPIRED")) {
            assertThatThrownBy(() -> sessions.refresh(pair.refreshToken(), CLIENT)).isInstanceOf(AuthException.class);
            assertThat(sessionRepository.findById(session.getId()).orElseThrow().getRevokedReason()).isEqualTo("REFRESH_EXPIRED");
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void exactExpiryBoundaryRejectsEvenWhenRevocationFlagsAreFalse(boolean sessionExpiry) {
        var pair = createSession();
        var jwt = decoder.decode(pair.accessToken());
        var token = refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow();
        var session = sessionRepository.findAll().getFirst();
        assertThat(token.isActive()).isTrue();
        assertThat(session.isRevoked()).isFalse();
        now.set(sessionExpiry ? session.getExpiresAt() : token.getExpiresAt());
        if (sessionExpiry) assertThat(sessions.isAccessSessionActive(jwt)).isFalse();
        assertThatThrownBy(() -> sessions.refresh(pair.refreshToken(), CLIENT)).isInstanceOf(AuthException.class);
        assertAllFamiliesRevoked();
        assertThat(refreshRepository.findById(token.getId()).orElseThrow().getConsumedAt()).isNull();
        assertThat(refreshRepository.count()).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void expiryDuringUserLookupDoesNotConsumeOrIssueTokens(boolean sessionExpiry) {
        var pair = createSession();
        var token = refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow();
        var session = sessionRepository.findAll().getFirst();
        doAnswer(invocation -> {
            now.set(sessionExpiry ? session.getExpiresAt() : token.getExpiresAt());
            return user;
        }).when(users).getUserById(42);
        assertThatThrownBy(() -> sessions.refresh(pair.refreshToken(), CLIENT)).isInstanceOf(AuthException.class);
        assertAllFamiliesRevoked();
        assertThat(refreshRepository.findById(token.getId()).orElseThrow().getConsumedAt()).isNull();
        assertThat(refreshRepository.count()).isEqualTo(1);
    }

    @Test
    void missingUserRevokesTheWholeTokenFamily() {
        var pair = createSession();
        var next = sessions.refresh(pair.refreshToken(), CLIENT);
        doThrow(new UserClientException(UserClientException.Code.NOT_FOUND, "GetUserById")).when(users).getUserById(42);
        assertThatThrownBy(() -> sessions.refresh(next.refreshToken(), CLIENT)).isInstanceOf(AuthException.class);
        assertAllFamiliesRevoked();
        assertThat(refreshRepository.count()).isEqualTo(2);
    }

    @Test
    void refreshExpiryAndAbsoluteSessionExpiryAreEnforced() {
        var first = createSession();
        now.updateAndGet(value -> value.plus(Duration.ofDays(8)));
        assertThatThrownBy(() -> sessions.refresh(first.refreshToken(), CLIENT)).isInstanceOf(AuthException.class);
        assertThat(sessionRepository.findAll().getFirst().getRevokedReason()).isEqualTo("REFRESH_EXPIRED");
        var second = createSession();
        now.updateAndGet(value -> value.plus(Duration.ofDays(31)));
        assertThatThrownBy(() -> sessions.refresh(second.refreshToken(), CLIENT)).isInstanceOf(AuthException.class);
    }

    @ParameterizedTest
    @EnumSource(value = UserAccount.AccountStatus.class, names = {"UNKNOWN", "PENDING_VERIFICATION", "SUSPENDED", "DEACTIVATED"})
    void inactiveAccountsCannotLoginOrReceiveOtp(UserAccount.AccountStatus status) throws Exception {
        setUser(account(status, 3, false, true));
        assertThat(password("user@example.com", "correct-password").getResponse().getStatus()).isEqualTo(401);
        assertThat(call("/login-otp-email", Map.of("email", "user@example.com")).getResponse().getStatus()).isEqualTo(200);
        verifyNoInteractions(notifications);
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void unverifiedContactAndExpiredCredentialsCannotReceiveOtp() throws Exception {
        setUser(account(UserAccount.AccountStatus.ACTIVE, 3, false, false));
        call("/login-otp-email", Map.of("email", "user@example.com"));
        verifyNoInteractions(notifications);
        clearCooldown();
        setUser(account(UserAccount.AccountStatus.ACTIVE, 3, true, true));
        assertThat(password("user@example.com", "correct-password").getResponse().getStatus()).isEqualTo(401);
        call("/login-otp-email", Map.of("email", "user@example.com"));
        verifyNoInteractions(notifications);
    }

    @Test
    void redisOutageFailsClosed() throws Exception {
        doThrow(new RedisConnectionFailureException("test outage")).when(protection).checkIp(any());
        var result = password("user@example.com", "correct-password");
        assertThat(result.getResponse().getStatus()).isEqualTo(503);
        assertThat(tree(result).path("code").asText()).isEqualTo("AUTH_SERVICE_UNAVAILABLE");
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void forgedForwardedHeaderDoesNotBypassIpLimit() throws Exception {
        properties.setIpMaxRequests(1);
        password("user@example.com", "wrong-password");
        mvc.perform(post("/api/v1/auth/login-password").header("X-Forwarded-For", "198.51.100.20")
                        .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(
                                Map.of("identifier", "user@example.com", "password", "correct-password"))))
                .andExpect(status().isTooManyRequests()).andExpect(jsonPath("$.code").value("RATE_LIMITED"));
    }

    @Test
    void ipLimitIsAtomicAndBlockedRequestsDoNotExtendItsWindow() throws Exception {
        properties.setIpMaxRequests(1);
        var results = race(() -> {
            protection.checkIp(CLIENT);
            return "SUCCESS";
        });
        assertThat(results).containsExactlyInAnyOrder("SUCCESS", "RATE_LIMITED");
        String key = "auth:ip:127.0.0.1";
        assertThat(redis.opsForValue().get(key)).isEqualTo("2");
        assertThat(redis.getExpire(key)).isPositive().isLessThanOrEqualTo(60L);
        redis.expire(key, Duration.ofSeconds(10));
        assertThatThrownBy(() -> protection.checkIp(CLIENT)).isInstanceOf(AuthException.class);
        assertThat(redis.getExpire(key)).isPositive().isLessThanOrEqualTo(10L);
        protection.checkIp(new ClientInfo("2001:db8::1", null, null));
        assertThat(redis.opsForValue().get("auth:ip:2001:db8::1")).isEqualTo("1");
        redis.expire(key, Duration.ZERO);
        protection.checkIp(CLIENT);
        assertThat(redis.opsForValue().get(key)).isEqualTo("1");
    }

    @Test
    void readableAccountFailureKeysStillShareLockoutAcrossEmailAndPhone() throws Exception {
        for (int i = 0; i < properties.getMaxFailedAttempts(); i++) {
            assertThat(password("USER@EXAMPLE.COM", "wrong-password").getResponse().getStatus()).isEqualTo(401);
        }
        assertThat(redis.opsForHash().get("auth:failure:identifier:user@example.com", "failures")).isEqualTo("5");
        assertThat(redis.opsForHash().get("auth:failure:account:42", "failures")).isEqualTo("5");
        var locked = password("09123456789", "correct-password");
        assertThat(locked.getResponse().getStatus()).isEqualTo(429);
        assertThat(tree(locked).path("code").asText()).isEqualTo("LOGIN_TEMPORARILY_LOCKED");
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void validationAndMalformedJsonDoNotEchoSecrets() throws Exception {
        mvc.perform(post("/api/v1/auth/login-password").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"identifier\":\"user@example.com\",\"password\":\"" + "s".repeat(100) + "\"}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_REQUEST"))
                .andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("s".repeat(100)))));
        mvc.perform(post("/api/v1/auth/verify").contentType(MediaType.APPLICATION_JSON).content("{broken-secret"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
    }

    @Test
    void changingOtpDestinationInvalidatesTheOldCodeEvenWithoutAPasswordChange() throws Exception {
        var challenge = startOtp();
        var changed = user.toBuilder().email("changed@example.com").build();
        doReturn(changed).when(users).getUserById(42);
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void upstreamIdentityMismatchCannotMintTokensForAnotherUser() throws Exception {
        var first = createSession();
        var wrongUser = user.toBuilder().userId(99).roles(List.of("ADMIN"))
                .email("other@example.com").phone(null).phoneVerified(false).build();
        doReturn(wrongUser).when(users).getUserById(42);
        assertThat(call("/refresh", Map.of("refreshToken", first.refreshToken())).getResponse().getStatus()).isEqualTo(503);
        assertThat(refreshRepository.findAll().getFirst().getConsumedAt()).isNull();
        assertThat(sessionRepository.count()).isEqualTo(1);
    }

    @Test
    void simultaneousOtpRequestsReserveTheCooldownOnlyOnce() throws Exception {
        var results = race(() -> {
            login.loginWithOtp("user@example.com", OtpChannel.EMAIL, CLIENT);
            return "SUCCESS";
        });
        assertThat(results).containsExactlyInAnyOrder("SUCCESS", "OTP_COOLDOWN");
        assertThat(redis.keys("auth:otp:{login}:challenge:*")).hasSize(1);
        verify(notifications, times(1)).sendLoginOtp(eq(42L), eq(OtpChannel.EMAIL), anyString(), anyString());
    }

    @Test
    void concurrentFailuresDoNotLoseIncrementsAndHaveExpiringState() throws Exception {
        String key = protection.identifierKey("user@example.com");
        var results = race(() -> {
            protection.failed(key, null);
            return "SUCCESS";
        });
        assertThat(results).containsExactly("SUCCESS", "SUCCESS");
        assertThat(redis.opsForHash().get("auth:failure:" + key, "failures")).isEqualTo("2");
        assertThat(redis.getExpire("auth:failure:" + key)).isPositive().isLessThanOrEqualTo(1800L);
    }

    @Test
    void progressiveLockIsCappedAndRequestsDoNotExtendIt() {
        String key = protection.identifierKey("progressive@example.com");
        for (int i = 0; i < 35; i++) {
            // Simulate waiting for each previous lock while retaining the observation window and failure count.
            redis.opsForHash().put("auth:failure:" + key, "lockedUntil", "0");
            protection.failed(key, null);
        }
        assertThat(redis.opsForHash().get("auth:failure:" + key, "failures")).isEqualTo("35");
        String until = String.valueOf(redis.opsForHash().get("auth:failure:" + key, "lockedUntil"));
        long remaining = Long.parseLong(until) - System.currentTimeMillis();
        assertThat(remaining).isBetween(1_790_000L, 1_800_000L);
        protection.failed(key, null);
        assertThat(redis.opsForHash().get("auth:failure:" + key, "lockedUntil")).isEqualTo(until);
        protection.clearFailures(key, 42);
        assertThat(protection.isLocked(key)).isTrue();
    }

    @Test
    void otpTableIsRemovedByMigration() throws Exception {
        try (var connection = dataSource.getConnection();
             var tables = connection.getMetaData().getTables(null, "public", "login_challenges", new String[]{"TABLE"})) {
            assertThat(tables.next()).isFalse();
        }
    }

    @Test
    void redisExpiryRemovesTheChallengeWithoutDatabaseCleanup() throws Exception {
        var challenge = startOtp();
        String key = "auth:otp:{login}:challenge:" + challenge.token();
        assertThat(redis.getExpire(key)).isPositive().isLessThanOrEqualTo(300L);
        redis.expire(key, Duration.ZERO);
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void claimCannotBeReleasedByAnotherVerifierAndDoesNotExtendExpiry() throws Exception {
        var challenge = startOtp();
        String token = challenge.token();
        String key = "auth:otp:{login}:challenge:" + token;
        long ttl = redis.getExpire(key);
        assertThat(challenges.claim(token, "first-owner")).isTrue();
        challenges.complete(token, "other-owner", false);
        assertThat(challenges.find(token).orElseThrow().state()).isEqualTo("CLAIMED");
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(401);
        assertThat(redis.getExpire(key)).isPositive().isLessThanOrEqualTo(ttl);
        challenges.complete(token, "first-owner", false);
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void wrongCodesDoNotResetChallengeLifetime() throws Exception {
        var challenge = startOtp();
        String key = "auth:otp:{login}:challenge:" + challenge.token();
        redis.expire(key, Duration.ofSeconds(30));
        String wrong = challenge.code().equals("000000") ? "000001" : "000000";
        assertThat(verifyOtp(challenge.token(), wrong).getResponse().getStatus()).isEqualTo(401);
        assertThat(redis.getExpire(key)).isPositive().isLessThanOrEqualTo(30L);
    }

    @Test
    void loginAndRefreshAuditFieldsIncludeRealIpAndClientMetadataWithoutCredentials() throws Exception {
        captureAuditLogs();
        var response = mvc.perform(post("/api/v1/auth/login-password").with(request -> {
                    request.setRemoteAddr("198.51.100.24"); return request;
                }).header("User-Agent", "audit-browser").header("X-Device-Id", "audit-device")
                .header("X-Forwarded-For", "203.0.113.99").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("identifier", "user@example.com", "password", "correct-password"))))
                .andExpect(status().isOk()).andReturn();
        var pair = tree(response).at("/data/tokens");
        assertThat(field(auditEvent("auth_request_received"), "path")).isEqualTo("/api/v1/auth/login-password");
        var success = auditEvent("login_success");
        assertThat(field(success, "ip_address")).isEqualTo("198.51.100.24");
        assertThat(field(success, "user_agent")).isEqualTo("audit-browser");
        assertThat(field(success, "device_id")).isEqualTo("audit-device");
        assertThat(field(success, "auth_method")).isEqualTo("PASSWORD");
        assertThat(success.getFormattedMessage()).isEqualTo("User logged in successfully.");
        mvc.perform(post("/api/v1/auth/refresh").with(request -> {
                    request.setRemoteAddr("198.51.100.25"); return request;
                }).header("User-Agent", "refresh-browser").header("X-Device-Id", "refresh-device")
                .contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(
                        Map.of("refreshToken", pair.path("refreshToken").asText()))))
                .andExpect(status().isOk());
        var rotated = auditEvent("refresh_rotated");
        assertThat(field(rotated, "ip_address")).isEqualTo("198.51.100.25");
        assertThat(field(rotated, "user_agent")).isEqualTo("refresh-browser");
        assertThat(field(rotated, "device_id")).isEqualTo("refresh-device");
        assertThat(field(rotated, "session_id")).isNotNull();
        assertNoCredentialLogs("correct-password", "user@example.com", PASSWORD_HASH,
                pair.path("accessToken").asText(), pair.path("refreshToken").asText());
    }

    @Test
    void otpAndInvalidInputFailuresKeepIpContextWithoutLoggingCodesOrBodies() throws Exception {
        captureAuditLogs();
        var challenge = startOtp();
        assertThat(field(auditEvent("otp_challenge_created"), "ip_address")).isEqualTo("127.0.0.1");
        String wrong = challenge.code().equals("000000") ? "000001" : "000000";
        verifyOtp(challenge.token(), wrong);
        var failure = auditEvent("otp_verification_failed");
        assertThat(field(failure, "ip_address")).isEqualTo("127.0.0.1");
        assertThat(field(failure, "attempts")).isEqualTo(1);
        assertThat(field(failure, "user_id")).isEqualTo(42L);
        mvc.perform(post("/api/v1/auth/verify").with(request -> {
                    request.setRemoteAddr("198.51.100.26"); return request;
                }).header("User-Agent", "invalid-browser").contentType(MediaType.APPLICATION_JSON).content("{raw-secret-body"))
                .andExpect(status().isBadRequest());
        var invalid = auditEvent("auth_request_failed");
        assertThat(field(invalid, "ip_address")).isEqualTo("198.51.100.26");
        assertThat(field(invalid, "status")).isEqualTo(400);
        assertThat(field(invalid, "path")).isEqualTo("/api/v1/auth/verify");
        assertNoCredentialLogs(challenge.token(), challenge.code(), wrong, "raw-secret-body", "user@example.com");
    }

    @Test
    void reuseAndUnknownRefreshAttemptsAreAuditedWithIpEvenWithoutANewSession() throws Exception {
        captureAuditLogs();
        var first = createSession();
        sessions.refresh(first.refreshToken(), CLIENT);
        assertThat(call("/refresh", Map.of("refreshToken", first.refreshToken())).getResponse().getStatus()).isEqualTo(401);
        var reuse = auditEvent("refresh_reuse_detected");
        assertThat(field(reuse, "ip_address")).isEqualTo("127.0.0.1");
        assertThat(field(reuse, "user_id")).isEqualTo(42L);
        auditLogs.list.clear();
        String unknown = tokens.randomToken();
        assertThat(call("/refresh", Map.of("refreshToken", unknown)).getResponse().getStatus()).isEqualTo(401);
        var rejected = auditEvent("auth_request_rejected");
        assertThat(field(rejected, "reason")).isEqualTo("INVALID_REFRESH_TOKEN");
        assertThat(field(rejected, "ip_address")).isEqualTo("127.0.0.1");
        assertThat(field(rejected, "path")).isEqualTo("/api/v1/auth/refresh");
        assertNoCredentialLogs(first.refreshToken(), first.accessToken(), unknown);
    }

    private void captureAuditLogs() {
        auditLogs = new ListAppender<>();
        auditLogs.setContext(auditLogger.getLoggerContext());
        auditLogs.start();
        auditLogger.addAppender(auditLogs);
    }

    private ILoggingEvent auditEvent(String name) {
        return auditLogs.list.stream().filter(event -> name.equals(field(event, "event"))).findFirst().orElseThrow();
    }

    private Object field(ILoggingEvent event, String name) {
        if (event.getKeyValuePairs() != null) {
            for (var pair : event.getKeyValuePairs()) if (pair.key.equals(name)) return pair.value;
        }
        return null;
    }

    private void assertNoCredentialLogs(String... secrets) {
        for (var event : auditLogs.list) {
            assertThat(event.getFormattedMessage()).doesNotContain(secrets);
            if (event.getKeyValuePairs() != null) {
                assertThat(event.getKeyValuePairs()).noneSatisfy(pair ->
                        assertThat(List.of(secrets)).contains(String.valueOf(pair.value)));
            }
        }
    }

    private void assertAllFamiliesRevoked() {
        assertThat(sessionRepository.findAll()).isNotEmpty().allSatisfy(session -> {
            assertThat(session.isRevoked()).isTrue();
            assertThat(session.getRevokedAt()).isNotNull();
        });
        assertThat(refreshRepository.findAll()).isNotEmpty().allSatisfy(token -> {
            assertThat(token.isActive()).isFalse();
            assertThat(token.getRevokedAt()).isNotNull();
        });
    }

    private void setRevocationState(String table, java.util.UUID id, boolean flagOnly) throws Exception {
        // Intentionally simulate independent revocation signals to ensure validation fails closed.
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("UPDATE " + table + " SET "
                     + (table.equals("refresh_tokens") ? "is_active" : "is_revoked") + " = ?, revoked_at = ? WHERE id = ?")) {
            statement.setBoolean(1, table.equals("refresh_tokens") ? !flagOnly : flagOnly);
            statement.setTimestamp(2, flagOnly ? null : java.sql.Timestamp.from(now.get()));
            statement.setObject(3, id);
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private UserAccount account(UserAccount.AccountStatus status, long version, boolean expired, boolean verified) {
        return UserAccount.builder()
                .userId(42)
                .roles(List.of("USER"))
                .email("user@example.com")
                .phone("+989123456789")
                .status(status)
                .emailVerified(verified)
                .phoneVerified(verified)
                .credentialVersion(version)
                .credentialsExpired(expired)
                .twoFactorEnabled(false)
                .build();
    }

    private AuthSettingDto enabledSettings(OtpChannel channel) {
        return AuthSettingDto.builder().loginEnabled(true).registerEnabled(true).defaultOtpChannel(channel)
                .emailNotificationEnabled(true).smsNotificationEnabled(true).inAppNotificationEnabled(true).build();
    }

    private AuthSettingDto disableChannel(AuthSettingDto current, OtpChannel channel) {
        var builder = current.toBuilder();
        switch (channel) {
            case EMAIL -> builder.emailNotificationEnabled(false);
            case SMS -> builder.smsNotificationEnabled(false);
            case IN_APP -> builder.inAppNotificationEnabled(false);
        }
        return builder.build();
    }

    private UserAccount twoFactorAccount() {
        return user.toBuilder().twoFactorEnabled(true).build();
    }

    private void setUser(UserAccount value) {
        doReturn(new UserLoginInfo(value, PASSWORD_HASH)).when(users).getLoginInfoByEmail("user@example.com");
        doReturn(new UserLoginInfo(value, PASSWORD_HASH)).when(users).getLoginInfoByPhone("+989123456789");
        doReturn(value).when(users).getUserById(42);
    }

    private ir.vigoapp.auth.dto.token.TokenResponse createSession() {
        return sessions.create(user, CLIENT);
    }

    private MvcResult password(String identifier, String password) throws Exception {
        return call("/login-password", Map.of("identifier", identifier, "password", password));
    }

    private MvcResult verifyOtp(String token, String code) throws Exception {
        return call("/verify", Map.of("mfaToken", token, "otp", code));
    }

    private MvcResult call(String path, Map<String, String> body) throws Exception {
        return mvc.perform(post("/api/v1/auth" + path).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(body))).andReturn();
    }

    private JsonNode tree(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    private Challenge startOtp() throws Exception {
        var response = call("/login-otp-email", Map.of("email", "user@example.com"));
        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        var code = ArgumentCaptor.forClass(String.class);
        verify(notifications, atLeastOnce()).sendLoginOtp(eq(42L), eq(OtpChannel.EMAIL), eq("user@example.com"), code.capture());
        return new Challenge(tree(response).at("/data/challenge/mfaToken").asText(), code.getAllValues().getLast());
    }

    private Challenge startPasswordOtp() throws Exception {
        var response = password("user@example.com", "correct-password");
        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        assertThat(tree(response).at("/data/step").asText()).isEqualTo("OTP_REQUIRED");
        var code = ArgumentCaptor.forClass(String.class);
        verify(notifications, atLeastOnce()).sendLoginOtp(eq(42L), eq(OtpChannel.EMAIL), eq("user@example.com"), code.capture());
        return new Challenge(tree(response).at("/data/challenge/mfaToken").asText(), code.getAllValues().getLast());
    }

    private void clearCooldown() {
        var keys = redis.keys("auth:otp-cooldown:*");
        if (keys != null && !keys.isEmpty()) redis.delete(keys);
    }

    private List<String> race(Callable<String> action) throws Exception {
        var barrier = new CyclicBarrier(2);
        Callable<String> contender = () -> {
            barrier.await(5, TimeUnit.SECONDS);
            try { return action.call(); }
            catch (AuthException exception) { return exception.getCode(); }
        };
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(contender);
            var second = executor.submit(contender);
            return List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS));
        }
    }

    private record Challenge(String token, String code) {}

    @TestConfiguration(proxyBeanMethods = false)
    static class TestDoubles {
        // The project's default Mockito maker supports interfaces only. Select subclass mocks locally.
        @Bean @Primary UserGrpcClient testUsers() { return classMock(UserGrpcClient.class); }
        @Bean @Primary AuthSettingService testSettings() { return classMock(AuthSettingService.class); }
        @Bean @Primary NotificationService testNotifications() { return classMock(NotificationService.class); }
        @Bean @Primary Clock testClock() { return classMock(Clock.class); }
        @Bean @Primary
        LoginProtectionService testProtection(StringRedisTemplate redis, AuthProperties properties, SecureTokens tokens) {
            return mock(LoginProtectionService.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS)
                    .spiedInstance(new LoginProtectionService(redis, properties, tokens)).defaultAnswer(CALLS_REAL_METHODS));
        }
        private static <T> T classMock(Class<T> type) {
            return mock(type, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
        }
    }
}
