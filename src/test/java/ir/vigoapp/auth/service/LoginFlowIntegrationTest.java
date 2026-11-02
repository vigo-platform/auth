package ir.vigoapp.auth.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.client.user.model.UserLoginInfo;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.dto.login.VerifyLoginRequest;
import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ir.vigoapp.auth.entity.OtpChannel;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.repository.AuthSessionRepository;
import ir.vigoapp.auth.service.login.OtpChallengeStore;
import ir.vigoapp.auth.repository.RefreshTokenRepository;
import ir.vigoapp.auth.security.SecureTokens;
import ir.vigoapp.auth.service.login.ClientInfo;
import ir.vigoapp.auth.service.login.LoginProtectionService;
import ir.vigoapp.auth.service.notification.NotificationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
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
    @Autowired OtpChallengeStore challenges;
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
        when(settings.getCurrent()).thenReturn(AuthSettingDto.builder().loginEnabled(true).defaultOtpChannel(OtpChannel.EMAIL).build());
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
                .doesNotContainKeys("codeHash", "destinationKey", "tokenHash");
        assertThat(challenges.find(challenge.token()).orElseThrow().toString()).doesNotContain(challenge.code(), challenge.token());
    }

    @Test
    void thirdWrongOtpDeletesTheChallengeAndEvenTheCorrectCodeThenFails() throws Exception {
        var challenge = startOtp();
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

    @Test
    void expiredOtpCannotIssueTokens() throws Exception {
        var challenge = startOtp();
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
    void concurrentOtpVerificationHasOnlyOneWinner() throws Exception {
        var challenge = startOtp();
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
                });
        assertThat(refreshRepository.findByTokenHash(tokens.hash(next.refreshToken())).orElseThrow())
                .satisfies(token -> {
                    assertThat(token.getIpAddress()).isEqualTo(nextClient.ipAddress());
                    assertThat(token.getUserAgent()).isEqualTo(nextClient.userAgent());
                    assertThat(token.getDeviceId()).isEqualTo(nextClient.deviceId());
                    assertThat(token.getConsumedAt()).isNotNull();
                });
        assertThat(refreshRepository.findByTokenHash(tokens.hash(last.refreshToken())).orElseThrow())
                .satisfies(token -> {
                    assertThat(token.getIpAddress()).isEqualTo(lastClient.ipAddress());
                    assertThat(token.getUserAgent()).isNull();
                    assertThat(token.getDeviceId()).isNull();
                    assertThat(token.getConsumedAt()).isNull();
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
    void credentialChangeRevokesEverySessionOnRefresh() throws Exception {
        var first = createSession();
        createSession();
        doReturn(account(UserAccount.AccountStatus.ACTIVE, 4, false, true)).when(users).getUserById(42);
        assertThat(call("/refresh", Map.of("refreshToken", first.refreshToken())).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.findAll()).allSatisfy(session -> assertThat(session.getRevokedReason()).isEqualTo("USER_STATE_CHANGED"));
        assertAllFamiliesRevoked();
    }

    @Test
    void userServiceFailureDoesNotConsumeRefreshTokenAndRetryCanSucceed() throws Exception {
        var first = createSession();
        doThrow(new UserClientException(UserClientException.Code.TIMEOUT, "GetUserById")).when(users).getUserById(42);
        var result = call("/refresh", Map.of("refreshToken", first.refreshToken()));
        assertThat(result.getResponse().getStatus()).isEqualTo(503);
        assertThat(refreshRepository.findAll().getFirst().getConsumedAt()).isNull();
        doReturn(user).when(users).getUserById(42);
        assertThat(call("/refresh", Map.of("refreshToken", first.refreshToken())).getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void userServiceFailureDoesNotConsumeCorrectOtp() throws Exception {
        var challenge = startOtp();
        doThrow(new UserClientException(UserClientException.Code.UNAVAILABLE, "GetUserById")).when(users).getUserById(42);
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(503);
        assertThat(challenges.find(challenge.token()).orElseThrow().state()).isEqualTo("OPEN");
        doReturn(user).when(users).getUserById(42);
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
        assertThat(refreshRepository.findAll()).filteredOn(t -> !t.isRevoked()).hasSize(2)
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
        assertThat(refreshRepository.findAll()).filteredOn(t -> t.isRevoked()).hasSize(3)
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
        assertThat(refreshRepository.findAll()).filteredOn(t -> t.isRevoked()).hasSize(3)
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
        assertThat(refreshRepository.count()).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void exactExpiryBoundaryRejectsEvenWhenRevocationFlagsAreFalse(boolean sessionExpiry) {
        var pair = createSession();
        var jwt = decoder.decode(pair.accessToken());
        var token = refreshRepository.findByTokenHash(tokens.hash(pair.refreshToken())).orElseThrow();
        var session = sessionRepository.findAll().getFirst();
        assertThat(token.isRevoked()).isFalse();
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
        var changed = new UserAccount(42, List.of("USER"), "changed@example.com", user.phone(), user.status(),
                true, true, 3, false);
        doReturn(changed).when(users).getUserById(42);
        assertThat(verifyOtp(challenge.token(), challenge.code()).getResponse().getStatus()).isEqualTo(401);
        assertThat(sessionRepository.count()).isZero();
    }

    @Test
    void upstreamIdentityMismatchCannotMintTokensForAnotherUser() throws Exception {
        var first = createSession();
        var wrongUser = new UserAccount(99, List.of("ADMIN"), "other@example.com", null, user.status(), true, false, 3, false);
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
            assertThat(token.isRevoked()).isTrue();
            assertThat(token.getRevokedAt()).isNotNull();
        });
    }

    private void setRevocationState(String table, java.util.UUID id, boolean flagOnly) throws Exception {
        // Intentionally simulate independent revocation signals to ensure validation fails closed.
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("UPDATE " + table + " SET is_revoked = ?, revoked_at = ? WHERE id = ?")) {
            statement.setBoolean(1, flagOnly);
            statement.setTimestamp(2, flagOnly ? null : java.sql.Timestamp.from(now.get()));
            statement.setObject(3, id);
            assertThat(statement.executeUpdate()).isEqualTo(1);
        }
    }

    private UserAccount account(UserAccount.AccountStatus status, long version, boolean expired, boolean verified) {
        return new UserAccount(42, List.of("USER"), "user@example.com", "+989123456789", status, verified, verified, version, expired);
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
