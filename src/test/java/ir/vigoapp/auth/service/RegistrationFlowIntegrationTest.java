package ir.vigoapp.auth.service;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.CreateUserCommand;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.config.JwtProperties;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.registration.*;
import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.model.OtpChallenge;
import ir.vigoapp.auth.repository.AuthSessionRepository;
import ir.vigoapp.auth.repository.OtpChallengeRepository;
import ir.vigoapp.auth.repository.RefreshTokenRepository;
import ir.vigoapp.auth.repository.registration.RegistrationRepository;
import ir.vigoapp.auth.security.SecureTokens;
import ir.vigoapp.auth.support.AuthFlowTestConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Disposable stores only: this test clears auth state, and uses no real notification or User mutation. */
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
@Import(AuthFlowTestConfiguration.class)
class RegistrationFlowIntegrationTest {
    private static final String PREFIX = "auth:registration:{registration}:";
    private static final ClientInfo CLIENT = ClientInfo.builder().ipAddress("127.0.0.1")
            .userAgent("registration-test").deviceId("registration-device").build();
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired RegistrationService registration;
    @Autowired RegistrationRepository registrations;
    @Autowired OtpChallengeRepository loginChallenges;
    @Autowired StringRedisTemplate redis;
    @Autowired UserGrpcClient users;
    @Autowired AuthSettingService settings;
    @Autowired NotificationService notifications;
    @Autowired AuthProtectionService protection;
    @Autowired PasswordEncoder passwords;
    @Autowired AuthProperties properties;
    @Autowired JwtProperties jwtProperties;
    @Autowired SecureTokens tokens;
    @Autowired Clock clock;
    @Autowired AuthSessionRepository sessions;
    @Autowired RefreshTokenRepository refreshTokens;
    @Autowired JwtDecoder decoder;
    private final AtomicReference<Instant> now = new AtomicReference<>();
    private AuthSettingDto current;
    private ListAppender<ILoggingEvent> auditLogs;
    private final Logger auditLogger = (Logger) LoggerFactory.getLogger("ir.vigoapp.auth");

    @BeforeEach
    void resetState() {
        reset(users, settings, notifications, protection, clock);
        refreshTokens.deleteAllInBatch();
        sessions.deleteAllInBatch();
        var keys = redis.keys("auth:*");
        if (keys != null && !keys.isEmpty()) redis.delete(keys);
        now.set(Instant.now());
        when(clock.instant()).thenAnswer(invocation -> now.get());
        properties.setIpMaxRequests(60);
        properties.setMaxFailedAttempts(5);
        properties.setOtpMaxAttempts(3);
        properties.setOtpTtl(Duration.ofMinutes(5));
        properties.setOtpCooldown(Duration.ofMinutes(1));
        properties.setRegistrationTokenTtl(Duration.ofMinutes(15));
        current = AuthSettingDto.builder().loginEnabled(true).registerEnabled(true).defaultOtpChannel(OtpChannel.EMAIL)
                .emailNotificationEnabled(true).smsNotificationEnabled(true).inAppNotificationEnabled(true).build();
        when(settings.getCurrent()).thenAnswer(invocation -> current);
        doAnswer(invocation -> created(invocation.getArgument(0))).when(users).createUser(any());
    }

    @AfterEach
    void detachAuditLogs() {
        if (auditLogs != null) {
            auditLogger.detachAppender(auditLogs);
            auditLogs.stop();
        }
    }

    @ParameterizedTest
    @CsvSource({"' NEW@EXAMPLE.COM ',new@example.com,EMAIL,true", "new@example.com,new@example.com,EMAIL,false",
            "00989111111111,+989111111111,SMS,true", "09111111111,+989111111111,SMS,false"})
    void completesVerifiedRegistrationAndIssuesTokensWhenLoginIsEnabled(String input, String normalized,
                                                                        OtpChannel channel, boolean loginEnabled) throws Exception {
        captureAuditLogs();
        current = current.toBuilder().loginEnabled(loginEnabled).defaultOtpChannel(OtpChannel.IN_APP).build();
        var challenge = start(input);
        verify(users, never()).createUser(any());
        var expiresAt = registrations.findChallenge(challenge.token()).orElseThrow().expiresAt();
        verify(notifications).sendRegistrationOtp(eq(channel), eq(normalized), eq(challenge.code()),
                argThat(expiry -> expiry.toEpochMilli() == expiresAt.toEpochMilli()), any());
        var verified = call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", challenge.code()));
        assertThat(verified.getResponse().getStatus()).isEqualTo(200);
        String proof = tree(verified).at("/data/registrationToken").asText();
        assertThat(tree(verified).at("/data/expiresIn").asLong()).isEqualTo(900);
        verify(users, never()).createUser(any());
        assertThat(sessions.count()).isZero();
        assertThat(refreshTokens.count()).isZero();
        var response = call("/register/complete", Map.of("registrationToken", proof, "password", " new-password ",
                "firstName", "Test", "lastName", "User"));
        assertThat(response.getResponse().getStatus()).isEqualTo(201);
        assertThat(response.getResponse().getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getResponse().getHeader("Pragma")).isEqualTo("no-cache");
        assertThat(tree(response).path("success").asBoolean()).isTrue();
        assertThat(tree(response).path("messageFa").asText()).isNotEmpty();
        assertThat(tree(response).at("/data/userId").asLong()).isEqualTo(42);
        assertThat(tree(response).at("/data/status").asText()).isEqualTo("ACTIVE");
        assertThat(tree(response).path("timestamp").asText()).endsWith("Z");
        var command = ArgumentCaptor.forClass(CreateUserCommand.class);
        verify(users).createUser(command.capture());
        assertThat(command.getValue()).satisfies(value -> {
            assertThat(value.email()).isEqualTo(channel == OtpChannel.EMAIL ? normalized : null);
            assertThat(value.phone()).isEqualTo(channel == OtpChannel.SMS ? normalized : null);
            assertThat(value.firstName()).isEqualTo("Test");
            assertThat(value.lastName()).isEqualTo("User");
            assertThat(passwords.matches(" new-password ", value.passwordHash())).isTrue();
        });
        var pair = tree(response).at("/data/tokens");
        if (loginEnabled) {
            assertThat(pair.path("tokenType").asText()).isEqualTo("Bearer");
            assertThat(pair.path("accessExpiresIn").asLong()).isPositive();
            assertThat(pair.path("refreshExpiresIn").asLong()).isPositive();
            String accessToken = pair.path("accessToken").asText();
            String refreshToken = pair.path("refreshToken").asText();
            var jwt = decoder.decode(accessToken);
            assertThat(jwt.getSubject()).isEqualTo("42");
            assertThat(jwt.getClaimAsStringList("roles")).containsExactly("USER");
            var sessionId = UUID.fromString(jwt.getClaimAsString("sid"));
            assertThat(sessions.findAll()).singleElement().satisfies(session -> {
                assertThat(session.getId()).isEqualTo(sessionId);
                assertThat(session.getUserId()).isEqualTo(42);
                assertThat(session.isActive(now.get())).isTrue();
            });
            assertThat(refreshTokens.findAll()).singleElement().satisfies(token -> {
                assertThat(token.getTokenHash()).isEqualTo(tokens.hash(refreshToken));
                assertThat(token.getIpAddress()).isEqualTo(CLIENT.ipAddress());
                assertThat(token.getUserAgent()).isEqualTo(CLIENT.userAgent());
                assertThat(token.getDeviceId()).isEqualTo(CLIENT.deviceId());
                assertThat(token.isActive()).isTrue();
            });
            assertThat(refreshTokens.findSessionIdByTokenHash(tokens.hash(refreshToken))).contains(sessionId);
            assertNoCredentialLogs(accessToken, refreshToken);
        } else {
            assertThat(pair.isMissingNode()).isTrue();
            assertThat(sessions.count()).isZero();
            assertThat(refreshTokens.count()).isZero();
        }
        assertThat(registrations.findChallenge(challenge.token())).isEmpty();
        assertThat(registrations.findGrant(proof)).isEmpty();
        assertThat(auditLogs.list).anySatisfy(event -> {
            assertThat(field(event, "event")).isEqualTo("registration_success");
            assertThat(field(event, "ip_address")).isEqualTo(CLIENT.ipAddress());
            assertThat(field(event, "user_agent")).isEqualTo(CLIENT.userAgent());
            assertThat(field(event, "device_id")).isEqualTo(CLIENT.deviceId());
            assertThat(field(event, "channel")).isEqualTo(channel);
        });
        assertNoCredentialLogs(challenge.token(), challenge.code(), proof, " new-password ",
                command.getValue().passwordHash(), normalized);
    }

    @Test
    void tokensFromRegistrationCompletionCanRefreshAndLogOut() throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        var response = complete(proof);
        assertThat(response.getResponse().getStatus()).isEqualTo(201);
        var pair = tree(response).at("/data/tokens");
        String accessToken = pair.path("accessToken").asText();
        String refreshToken = pair.path("refreshToken").asText();
        var account = created(CreateUserCommand.builder().email("new@example.com").build());
        when(users.getUserById(account.userId())).thenReturn(account);

        var refreshed = call("/refresh", Map.of("refreshToken", refreshToken));
        assertThat(refreshed.getResponse().getStatus()).isEqualTo(200);
        String nextRefresh = tree(refreshed).at("/data/refreshToken").asText();
        assertThat(nextRefresh).isNotBlank().isNotEqualTo(refreshToken);
        var original = refreshTokens.findByTokenHash(tokens.hash(refreshToken)).orElseThrow();
        assertThat(original.isActive()).isFalse();
        assertThat(original.getConsumedAt()).isNotNull();

        var logout = mvc.perform(post("/api/v1/auth/logout").header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andReturn();
        assertThat(logout.getResponse().getStatus()).isEqualTo(200);
        assertThat(sessions.findAll()).singleElement().satisfies(session ->
                assertThat(session.getRevokedReason()).isEqualTo("LOGOUT"));
        assertError(call("/refresh", Map.of("refreshToken", nextRefresh)), 401, "INVALID_REFRESH_TOKEN");
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void disabledRegistrationGatesAllStagesRegardlessOfTheLoginSetting(boolean loginEnabled) throws Exception {
        current = current.toBuilder().loginEnabled(loginEnabled).registerEnabled(false).build();
        for (var request : Map.of(
                "/register/initiate", Map.of("identifier", "new@example.com"),
                "/register/verify", Map.of("mfaToken", tokens.randomToken(), "otp", "012345"),
                "/register/complete", Map.of("registrationToken", tokens.randomToken(), "password", "new-password")).entrySet()) {
            assertError(call(request.getKey(), request.getValue()), 503, "REGISTRATION_DISABLED");
        }
        verifyNoInteractions(users, notifications, protection);
        assertThat(redis.keys("auth:*")).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({"new@example.com,EMAIL", "09111111111,SMS"})
    void disabledChannelBlocksIssuanceWithoutFallbackOrExternalWork(String identifier, OtpChannel channel) throws Exception {
        disableChannel(channel);
        assertError(call("/register/initiate", Map.of("identifier", identifier)), 503, "OTP_CHANNEL_DISABLED");
        verifyNoInteractions(users, notifications, protection);
        assertThat(redis.keys(PREFIX + "*")).isEmpty();
    }

    @ParameterizedTest
    @CsvSource({"new@example.com,EMAIL", "09111111111,SMS"})
    void disablingAChannelPausesVerificationAndCompletionWithoutConsumingProofs(String identifier, OtpChannel channel) throws Exception {
        var challenge = start(identifier);
        disableChannel(channel);
        assertError(call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", challenge.code())),
                503, "OTP_CHANNEL_DISABLED");
        assertThat(registrations.findChallenge(challenge.token()).orElseThrow().failedAttempts()).isZero();
        enableChannels();
        String proof = verifyChallenge(challenge);
        disableChannel(channel);
        assertError(complete(proof), 503, "OTP_CHANNEL_DISABLED");
        assertThat(registrations.findGrant(proof).orElseThrow().isOpen()).isTrue();
        verify(users, never()).createUser(any());
        enableChannels();
        assertThat(complete(proof).getResponse().getStatus()).isEqualTo(201);
    }

    @Test
    void disablingRegistrationAfterIssuancePreservesTheChallengeAndGrantForReenablement() throws Exception {
        var challenge = start("new@example.com");
        current = current.toBuilder().registerEnabled(false).build();
        assertError(call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", challenge.code())),
                503, "REGISTRATION_DISABLED");
        current = current.toBuilder().registerEnabled(true).build();
        String proof = verifyChallenge(challenge);
        current = current.toBuilder().registerEnabled(false).build();
        assertError(complete(proof), 503, "REGISTRATION_DISABLED");
        assertThat(registrations.findGrant(proof).orElseThrow().isOpen()).isTrue();
        current = current.toBuilder().registerEnabled(true).build();
        assertThat(complete(proof).getResponse().getStatus()).isEqualTo(201);
    }

    @Test
    void aSettingsChangeDuringExistenceLookupPreventsChallengeCreationAndDelivery() throws Exception {
        when(users.checkEmailExists("new@example.com")).thenAnswer(invocation -> {
            current = current.toBuilder().emailNotificationEnabled(false).build();
            return false;
        });
        assertError(call("/register/initiate", Map.of("identifier", "new@example.com")), 503, "OTP_CHANNEL_DISABLED");
        assertThat(redis.keys(PREFIX + "*")).isEmpty();
        verifyNoInteractions(notifications);
    }

    @Test
    void aSettingsChangeDuringTheClaimReleasesItBeforeAnyRemoteCreation() throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        var clockReads = new AtomicInteger();
        doAnswer(invocation -> {
            if (clockReads.incrementAndGet() == 2) current = current.toBuilder().registerEnabled(false).build();
            return now.get();
        }).when(clock).instant();
        assertError(complete(proof), 503, "REGISTRATION_DISABLED");
        verify(users, never()).createUser(any());
        assertThat(registrations.findGrant(proof).orElseThrow().isOpen()).isTrue();
        doAnswer(invocation -> now.get()).when(clock).instant();
        current = current.toBuilder().registerEnabled(true).build();
        assertThat(complete(proof).getResponse().getStatus()).isEqualTo(201);
    }

    @Test
    void aProofExpiringDuringPasswordHashingCannotCreateAnAccount() throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        var clockReads = new AtomicInteger();
        doAnswer(invocation -> clockReads.incrementAndGet() == 1 ? now.get()
                : now.get().plus(properties.getRegistrationTokenTtl())).when(clock).instant();
        assertError(complete(proof), 401, "INVALID_REGISTRATION_TOKEN");
        verify(users, never()).createUser(any());
    }

    @Test
    void otpExpiryAndAttemptLimitCannotBeResetByResending() throws Exception {
        var challenge = start("new@example.com");
        String wrong = challenge.code().equals("000000") ? "111111" : "000000";
        for (int i = 1; i <= 3; i++) {
            assertError(call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", wrong)), 401, "INVALID_OTP");
        }
        assertThat(registrations.findChallenge(challenge.token())).isEmpty();
        // Even the correct code cannot revive a challenge after its attempt budget is exhausted.
        for (int i = 0; i < 10; i++) {
            assertError(call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", challenge.code())),
                    401, "INVALID_OTP");
        }
        assertThat(redis.keys(PREFIX + "grant:*")).isEmpty();
        var cooldown = call("/register/initiate", Map.of("identifier", " NEW@EXAMPLE.COM "));
        assertError(cooldown, 429, "OTP_COOLDOWN");
        assertThat(Long.parseLong(cooldown.getResponse().getHeader("Retry-After"))).isPositive();
        assertThat(tree(cooldown).at("/data/retryAfterSeconds").asLong()).isPositive();
        clearCooldown("new@example.com");
        var next = start("new@example.com");
        long ttl = redis.getExpire(PREFIX + "challenge:" + next.token(), TimeUnit.MILLISECONDS);
        String nextWrong = next.code().equals("000000") ? "111111" : "000000";
        for (int i = 0; i < 2; i++) {
            assertError(call("/register/verify", Map.of("mfaToken", next.token(), "otp", nextWrong)), 401, "INVALID_OTP");
        }
        assertError(call("/register/verify", Map.of("mfaToken", next.token(), "otp", next.code())),
                429, "LOGIN_TEMPORARILY_LOCKED");
        assertThat(redis.getExpire(PREFIX + "challenge:" + next.token(), TimeUnit.MILLISECONDS)).isLessThanOrEqualTo(ttl);
        verify(users, never()).createUser(any());
    }

    @Test
    void resendingReplacesTheOldChallengeAndAllPhoneFormatsShareOneCooldown() throws Exception {
        var old = start("09111111111");
        assertError(call("/register/initiate", Map.of("identifier", "+989111111111")), 429, "OTP_COOLDOWN");
        clearCooldown("+989111111111");
        var replacement = start("00989111111111");
        assertThat(registrations.findChallenge(old.token())).isEmpty();
        assertError(call("/register/verify", Map.of("mfaToken", old.token(), "otp", old.code())), 401, "INVALID_OTP");
        assertThat(verifyChallenge(replacement)).hasSize(43);
    }

    @Test
    void leadingZerosArePreservedAndOneCodeCannotProduceTwoProofs() throws Exception {
        var challenge = start("new@example.com");
        redis.opsForHash().put(PREFIX + "challenge:" + challenge.token(), "code", "012345");
        var response = call("/register/verify", Map.of("mfa_token", challenge.token(), "otp", "012345"));
        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        assertError(call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", "012345")), 401, "INVALID_OTP");
        assertThat(redis.keys(PREFIX + "grant:*")).hasSize(1);
    }

    @Test
    void expiryAtEitherStagePreventsAnyAccountCreation() throws Exception {
        var challenge = start("new@example.com");
        now.set(now.get().plus(properties.getOtpTtl()));
        assertError(call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", challenge.code())), 401, "INVALID_OTP");
        assertThat(redis.keys(PREFIX + "grant:*")).isEmpty();
        clearCooldown("new@example.com");
        String proof = verifyChallenge(start("new@example.com"));
        now.set(now.get().plus(properties.getRegistrationTokenTtl()));
        assertError(complete(proof), 401, "INVALID_REGISTRATION_TOKEN");
        verify(users, never()).createUser(any());
    }

    @ParameterizedTest
    @CsvSource({"new@example.com,EMAIL", "09111111111,SMS"})
    void existingContactsHaveAUsefulConflictAndReceiveNoCode(String identifier, OtpChannel channel) throws Exception {
        if (channel == OtpChannel.EMAIL) when(users.checkEmailExists("new@example.com")).thenReturn(true);
        else when(users.checkPhoneExists("+989111111111")).thenReturn(true);
        assertError(call("/register/initiate", Map.of("identifier", identifier)), 409, "ACCOUNT_ALREADY_EXISTS");
        assertThat(redis.keys(PREFIX + "challenge:*")).isEmpty();
        verifyNoInteractions(notifications);
    }

    @Test
    void registrationTokensAndLoginChallengesAreNotInterchangeable() throws Exception {
        var guest = start("new@example.com");
        assertError(call("/verify", Map.of("mfaToken", guest.token(), "otp", guest.code())), 401, "INVALID_OTP");
        assertError(complete(guest.token()), 401, "INVALID_REGISTRATION_TOKEN");
        String loginToken = tokens.randomToken();
        loginChallenges.create(OtpChallenge.builder().token(loginToken).identifierKey("identifier:existing@example.com")
                .destination("existing@example.com").userId(42).credentialVersion(1).code("012345")
                .channel(OtpChannel.EMAIL).expiresAt(now.get().plusSeconds(300)).state("OPEN").build(), "account:42");
        assertError(call("/register/verify", Map.of("mfaToken", loginToken, "otp", "012345")), 401, "INVALID_OTP");
        assertError(complete(loginToken), 401, "INVALID_REGISTRATION_TOKEN");
        String proof = verifyChallenge(guest);
        assertError(call("/verify", Map.of("mfaToken", proof, "otp", guest.code())), 401, "INVALID_OTP");
        verify(users, never()).createUser(any());
        assertThat(sessions.count()).isZero();
    }

    @Test
    void concurrentVerifiersCreateExactlyOneProof() throws Exception {
        var challenge = start("new@example.com");
        var barrier = new CyclicBarrier(2);
        java.util.concurrent.Callable<String> action = () -> {
            barrier.await(5, TimeUnit.SECONDS);
            try {
                return registration.verify(RegistrationVerifyRequest.builder().mfaToken(challenge.token())
                        .otp(challenge.code()).build(), CLIENT).registrationToken();
            } catch (AuthException exception) { return exception.getCode(); }
        };
        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(action);
            var second = executor.submit(action);
            assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
                    .filteredOn(value -> !value.equals("INVALID_OTP")).hasSize(1);
        }
        assertThat(redis.keys(PREFIX + "grant:*")).hasSize(1);
    }

    @Test
    void concurrentCompletionClaimsOnceAndRejectsAConsumedProof() throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        var entered = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        doAnswer(invocation -> {
            entered.countDown();
            if (!release.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("test timeout");
            return created(invocation.getArgument(0));
        }).when(users).createUser(any());
        try (var executor = Executors.newSingleThreadExecutor()) {
            var first = executor.submit(() -> registration.complete(RegisterRequest.builder()
                    .registrationToken(proof).password("new-password").build(), CLIENT));
            try {
                assertThat(entered.await(10, TimeUnit.SECONDS)).isTrue();
                assertError(complete(proof), 409, "REGISTRATION_IN_PROGRESS");
            } finally { release.countDown(); }
            assertThat(first.get(10, TimeUnit.SECONDS).userId()).isEqualTo(42);
        }
        var retry = call("/register/complete", Map.of("registration_token", proof, "password", "different-password"));
        assertError(retry, 401, "INVALID_REGISTRATION_TOKEN");
        assertThat(registrations.findGrant(proof)).isEmpty();
        verify(users, times(1)).createUser(any());
        assertThat(sessions.count()).isEqualTo(1);
        assertThat(refreshTokens.count()).isEqualTo(1);
    }

    @Test
    void successfulCompletionConsumesBothStepsAndTenIdenticalRetriesAreRejected() throws Exception {
        var challenge = start("new@example.com");
        String proof = verifyChallenge(challenge);
        var body = Map.of("registrationToken", proof, "password", "example-password", "firstName", "Test", "lastName", "User");
        assertThat(call("/register/complete", body).getResponse().getStatus()).isEqualTo(201);
        assertThat(registrations.findChallenge(challenge.token())).isEmpty();
        assertThat(registrations.findGrant(proof)).isEmpty();
        for (int i = 0; i < 10; i++) {
            assertError(call("/register/complete", body), 401, "INVALID_REGISTRATION_TOKEN");
        }
        assertError(call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", challenge.code())), 401, "INVALID_OTP");
        verify(users, times(1)).createUser(any());
        assertThat(sessions.count()).isEqualTo(1);
        assertThat(refreshTokens.count()).isEqualTo(1);
    }

    @Test
    void aTokenSigningFailureRollsBackSessionCreationAndDoesNotReopenTheProof() throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        String signingKey = jwtProperties.getKeyId();
        try {
            jwtProperties.setKeyId("unavailable-signing-key");
            assertError(complete(proof), 500, "INTERNAL_ERROR");
        } finally {
            jwtProperties.setKeyId(signingKey);
        }

        assertThat(sessions.count()).isZero();
        assertThat(refreshTokens.count()).isZero();
        assertThat(registrations.findGrant(proof)).isEmpty();
        assertError(complete(proof), 401, "INVALID_REGISTRATION_TOKEN");
        verify(users, times(1)).createUser(any());
    }

    @Test
    void completedResultsLeftByTheOldVersionNeverReturnSuccess() throws Exception {
        String proof = tokens.randomToken();
        redis.opsForHash().putAll(PREFIX + "grant:" + proof, Map.of("identifier", "new@example.com", "channel", "EMAIL",
                "expiresAt", Long.toString(now.get().plusSeconds(900).toEpochMilli()), "state", "COMPLETED",
                "userId", "4", "status", "ACTIVE"));
        redis.expire(PREFIX + "grant:" + proof, Duration.ofMinutes(15));
        assertError(complete(proof), 401, "INVALID_REGISTRATION_TOKEN");
        verifyNoInteractions(users, notifications);
    }

    @Test
    void onlyTheClaimOwnerCanConsumeAProofAndReleaseCannotResurrectIt() throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        assertThat(registrations.claim(proof, "owner", now.get())).isTrue();
        assertThat(registrations.complete(proof, "other-owner")).isFalse();
        registrations.release(proof, "other-owner");
        assertThat(registrations.findGrant(proof).orElseThrow().isClaimed()).isTrue();
        assertThat(registrations.complete(proof, "owner")).isTrue();
        registrations.release(proof, "owner");
        assertThat(registrations.findGrant(proof)).isEmpty();
        assertError(complete(proof), 401, "INVALID_REGISTRATION_TOKEN");
        verify(users, never()).createUser(any());
    }

    @ParameterizedTest
    @CsvSource({"ALREADY_EXISTS,409,ACCOUNT_ALREADY_EXISTS", "INVALID_ARGUMENT,400,INVALID_REQUEST",
            "TIMEOUT,503,AUTH_SERVICE_UNAVAILABLE", "UNAVAILABLE,503,AUTH_SERVICE_UNAVAILABLE"})
    void userErrorsAreSafeAndOnlyDefinitiveRejectionsReleaseTheClaim(UserClientException.Code code,
                                                                   int status, String error) throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        doThrow(new UserClientException(code, "CreateUser")).when(users).createUser(any());
        var response = complete(proof);
        assertError(response, status, error);
        assertThat(response.getResponse().getContentAsString()).doesNotContain("new-password", proof);
        assertThat(registrations.findGrant(proof).orElseThrow().isOpen())
                .isEqualTo(code == UserClientException.Code.INVALID_ARGUMENT);
        if (code != UserClientException.Code.INVALID_ARGUMENT) {
            assertError(complete(proof), 409, "REGISTRATION_IN_PROGRESS");
            verify(users, times(1)).createUser(any());
        } else {
            doAnswer(invocation -> created(invocation.getArgument(0))).when(users).createUser(any());
            assertThat(complete(proof).getResponse().getStatus()).isEqualTo(201);
        }
    }

    @Test
    void anUpstreamIdentityMismatchCannotBeReportedAsSuccessOrRetriedAsAMutation() throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        doReturn(created(CreateUserCommand.builder().email("different@example.com").build())).when(users).createUser(any());
        assertError(complete(proof), 503, "AUTH_SERVICE_UNAVAILABLE");
        assertError(complete(proof), 409, "REGISTRATION_IN_PROGRESS");
        verify(users, times(1)).createUser(any());
    }

    @Test
    void equivalentLocalFormatInTheUserResponseStillMatchesTheProvenPhone() throws Exception {
        String proof = verifyChallenge(start("09111111111"));
        doReturn(created(CreateUserCommand.builder().phone("09111111111").build())).when(users).createUser(any());
        assertThat(complete(proof).getResponse().getStatus()).isEqualTo(201);
    }

    @Test
    void incorrectCodesAndMalformedBodiesAreAuditedWithoutTheirContents() throws Exception {
        captureAuditLogs();
        var challenge = start("new@example.com");
        String wrong = challenge.code().equals("000000") ? "111111" : "000000";
        assertError(call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", wrong)), 401, "INVALID_OTP");
        var invalid = mvc.perform(post("/api/v1/auth/register/verify").contentType(MediaType.APPLICATION_JSON)
                .content("{raw-secret-registration-body")).andReturn();
        assertThat(invalid.getResponse().getStatus()).isEqualTo(400);
        assertThat(auditLogs.list).anySatisfy(event -> {
            assertThat(field(event, "event")).isEqualTo("registration_otp_rejected");
            assertThat(field(event, "reason")).isEqualTo("incorrect_code");
            assertThat(field(event, "attempts")).isEqualTo(1);
        });
        assertNoCredentialLogs(challenge.token(), challenge.code(), wrong, "raw-secret-registration-body", "new@example.com");
    }

    @Test
    void grantExpiryDuringUserCreationDoesNotTurnACommittedSuccessIntoAnError() throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        doAnswer(invocation -> {
            redis.delete(PREFIX + "grant:" + proof);
            return created(invocation.getArgument(0));
        }).when(users).createUser(any());
        assertThat(complete(proof).getResponse().getStatus()).isEqualTo(201);
        assertError(complete(proof), 401, "INVALID_REGISTRATION_TOKEN");
        verify(users, times(1)).createUser(any());
    }

    @Test
    void notificationDeliveryFailureRemovesTheUnsentChallenge() throws Exception {
        doThrow(new AuthException(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE,
                "OTP_DELIVERY_UNAVAILABLE", "Test delivery failure.", "خطای ارسال آزمایشی."))
                .when(notifications).sendRegistrationOtp(any(), anyString(), anyString(), any(), any());
        assertError(call("/register/initiate", Map.of("identifier", "new@example.com")), 503, "OTP_DELIVERY_UNAVAILABLE");
        assertThat(redis.keys(PREFIX + "challenge:*")).isEmpty();
        assertThat(redis.keys(PREFIX + "grant:*")).isEmpty();
    }

    @ParameterizedTest
    @ValueSource(strings = {"/register/initiate", "/register/verify", "/register/complete"})
    void allStagesUseTheSharedIpLimit(String path) throws Exception {
        var challenge = start("new@example.com");
        String proof = verifyChallenge(challenge);
        properties.setIpMaxRequests(1);
        var body = switch (path) {
            case "/register/initiate" -> Map.of("identifier", "other@example.com");
            case "/register/verify" -> Map.of("mfaToken", tokens.randomToken(), "otp", "012345");
            default -> Map.of("registrationToken", proof, "password", "new-password");
        };
        assertError(call(path, body), 429, "RATE_LIMITED");
        verify(users, never()).createUser(any());
    }

    @Test
    void redisFailureStopsTheFlowBeforeAnyAccountLookupOrCreation() throws Exception {
        doThrow(new RedisConnectionFailureException("test failure")).when(protection).checkIp(any());
        assertError(call("/register/initiate", Map.of("identifier", "new@example.com")), 503, "AUTH_SERVICE_UNAVAILABLE");
        verifyNoInteractions(users, notifications);
    }

    @ParameterizedTest
    @CsvSource({"/register/initiate,{}", "/register/initiate,'{\"identifier\":\"invalid\"}'",
            "/register/verify,'{\"mfaToken\":\"bad\",\"otp\":\"012345\"}'",
            "/register/complete,'{\"email\":\"new@example.com\",\"password\":\"new-password\"}'"})
    void malformedRequestsAndTheOldDirectSignupCannotCreateAccounts(String path, String body) throws Exception {
        var response = mvc.perform(post("/api/v1/auth" + path).contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
        assertThat(response.getResponse().getStatus()).isEqualTo(400);
        assertThat(response.getResponse().getContentAsString()).doesNotContain("new-password");
        verifyNoInteractions(users, notifications);
    }

    @Test
    void invalidPasswordsDoNotConsumeTheProofAndUnverifiedContactsCannotBeAdded() throws Exception {
        String proof = verifyChallenge(start("new@example.com"));
        assertError(call("/register/complete", Map.of("registrationToken", proof, "password", "short")), 400, "INVALID_REQUEST");
        assertError(call("/register/complete", Map.of("registrationToken", proof, "password", "پ".repeat(37))),
                400, "INVALID_PASSWORD_LENGTH");
        assertThat(registrations.findGrant(proof).orElseThrow().isOpen()).isTrue();
        var tampered = call("/register/complete", Map.of("registrationToken", proof, "password", "new-password",
                "email", "attacker@example.com", "phone", "09123456789"));
        assertThat(tampered.getResponse().getStatus()).isEqualTo(201);
        var command = ArgumentCaptor.forClass(CreateUserCommand.class);
        verify(users).createUser(command.capture());
        assertThat(command.getValue().email()).isEqualTo("new@example.com");
        assertThat(command.getValue().phone()).isNull();
    }

    private Challenge start(String identifier) throws Exception {
        var response = call("/register/initiate", Map.of("identifier", identifier));
        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        assertThat(tree(response).at("/data/expiresIn").asLong()).isEqualTo(300);
        assertThat(tree(response).at("/data/resendAfter").asLong()).isEqualTo(60);
        String token = tree(response).at("/data/mfaToken").asText();
        assertThat(token).hasSize(43);
        String code = redis.<String, String>opsForHash().get(PREFIX + "challenge:" + token, "code");
        assertThat(code).matches("[0-9]{6}");
        return new Challenge(token, code);
    }

    private String verifyChallenge(Challenge challenge) throws Exception {
        var response = call("/register/verify", Map.of("mfaToken", challenge.token(), "otp", challenge.code()));
        assertThat(response.getResponse().getStatus()).isEqualTo(200);
        return tree(response).at("/data/registrationToken").asText();
    }

    private MvcResult complete(String proof) throws Exception {
        return call("/register/complete", Map.of("registrationToken", proof, "password", "new-password"));
    }

    private MvcResult call(String path, Map<String, String> body) throws Exception {
        return mvc.perform(post("/api/v1/auth" + path).contentType(MediaType.APPLICATION_JSON)
                .with(request -> { request.setRemoteAddr(CLIENT.ipAddress()); return request; })
                .header("User-Agent", CLIENT.userAgent()).header("X-Device-Id", CLIENT.deviceId())
                .content(json.writeValueAsString(body))).andReturn();
    }

    private JsonNode tree(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    private void assertError(MvcResult result, int status, String code) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(status);
        assertThat(tree(result).path("code").asText()).isEqualTo(code);
        assertThat(result.getResponse().getHeader("Cache-Control")).isEqualTo("no-store");
    }

    private UserAccount created(CreateUserCommand command) {
        return UserAccount.builder().userId(42).roles(List.of("USER")).email(command.email()).phone(command.phone())
                .status(UserAccount.AccountStatus.ACTIVE).emailVerified(command.email() != null)
                .phoneVerified(command.phone() != null).credentialVersion(1).build();
    }

    private void clearCooldown(String identifier) { redis.delete("auth:otp-cooldown:identifier:" + identifier); }

    private void disableChannel(OtpChannel channel) {
        current = channel == OtpChannel.EMAIL ? current.toBuilder().emailNotificationEnabled(false).build()
                : current.toBuilder().smsNotificationEnabled(false).build();
    }

    private void enableChannels() {
        current = current.toBuilder().emailNotificationEnabled(true).smsNotificationEnabled(true).build();
    }

    private void captureAuditLogs() {
        auditLogs = new ListAppender<>();
        auditLogs.setContext(auditLogger.getLoggerContext());
        auditLogs.start();
        auditLogger.addAppender(auditLogs);
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

    private record Challenge(String token, String code) {}
}
