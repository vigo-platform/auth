package ir.vigoapp.auth.repository.password;

import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.model.password.PasswordChallenge;
import ir.vigoapp.auth.model.password.PasswordGrant;
import ir.vigoapp.auth.model.password.PasswordPurpose;
import ir.vigoapp.auth.security.SecureTokens;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "AUTH_TEST_REDIS_PORT", matches = "[0-9]+")
class PasswordRepositoryIntegrationTest {
    private final long userId = ThreadLocalRandom.current().nextLong(1, Long.MAX_VALUE);
    private LettuceConnectionFactory connections;
    private PasswordRepository passwords;
    private SecureTokens tokens;

    @BeforeEach
    void connect() {
        connections = new LettuceConnectionFactory("127.0.0.1", Integer.parseInt(System.getenv("AUTH_TEST_REDIS_PORT")));
        connections.afterPropertiesSet();
        connections.start();
        var properties = new AuthProperties();
        properties.setOtpSecret("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        tokens = new SecureTokens(properties);
        passwords = new PasswordRepository(new StringRedisTemplate(connections), properties, tokens, Clock.systemUTC());
    }

    @AfterEach
    void disconnect() {
        if (connections != null) connections.destroy();
    }

    @Test
    void resetCodesCanAdvanceAndExchangeOnceOnlyForTheirPurpose() {
        String firstToken = tokens.randomToken();
        String nextToken = tokens.randomToken();
        String grantToken = tokens.randomToken();
        var first = PasswordChallenge.builder().purpose(PasswordPurpose.RESET).userId(userId).credentialVersion(1)
                .identifierKey("password-reset:identifier:test@example.com").channel(OtpChannel.EMAIL)
                .destination("test@example.com").expiresAt(Instant.now().plusSeconds(30)).build();
        var next = PasswordChallenge.builder().purpose(PasswordPurpose.RESET).userId(userId).credentialVersion(1)
                .identifierKey(first.identifierKey()).channel(OtpChannel.SMS).destination("+989111111111")
                .previousChannel(first.channel()).previousDestination(first.destination())
                .expiresAt(Instant.now().plusSeconds(30)).build();
        var grant = PasswordGrant.builder().purpose(PasswordPurpose.RESET).userId(userId).credentialVersion(1)
                .channel(next.channel()).destination(next.destination()).otherChannel(first.channel())
                .otherDestination(first.destination()).expiresAt(Instant.now().plusSeconds(30)).build();

        passwords.createChallenge(firstToken, first, "111111");
        assertThat(passwords.advance(firstToken, PasswordPurpose.RESET, "111111", nextToken, next, "111111")).isZero();
        assertThat(passwords.advance(firstToken, PasswordPurpose.RESET, "111111", nextToken, next, "222222")).isOne();
        assertThat(passwords.findChallenge(firstToken)).isEmpty();
        assertThat(passwords.verify(nextToken, PasswordPurpose.CHANGE, "222222", grantToken, grant)).isZero();
        assertThat(passwords.verify(nextToken, PasswordPurpose.RESET, "111111", grantToken, grant)).isEqualTo(-1);
        assertThat(passwords.verify(nextToken, PasswordPurpose.RESET, "222222", grantToken, grant)).isOne();
        assertThat(passwords.verify(nextToken, PasswordPurpose.RESET, "222222", tokens.randomToken(), grant)).isZero();
        assertThat(passwords.findGrant(grantToken)).get().satisfies(stored -> {
            assertThat(stored.isOpen()).isTrue();
            assertThat(stored.otherChannel()).isEqualTo(OtpChannel.EMAIL);
        });
    }

    @Test
    void onlyOneConcurrentClaimWinsAndOnlyItsOwnerCanSpendTheGrant() throws Exception {
        String token = tokens.randomToken();
        var grant = PasswordGrant.builder().purpose(PasswordPurpose.EXPIRED).userId(userId).credentialVersion(1)
                .passwordVerified(true).expiresAt(Instant.now().plusSeconds(30)).build();
        passwords.createGrant(token, grant);
        assertThat(passwords.claim(token, PasswordPurpose.RESET, "reset-owner")).isZero();

        try (var tasks = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var first = tasks.submit(() -> passwords.claim(token, PasswordPurpose.EXPIRED, "first"));
            var second = tasks.submit(() -> passwords.claim(token, PasswordPurpose.EXPIRED, "second"));
            int firstResult = first.get(5, TimeUnit.SECONDS);
            assertThat(new int[]{firstResult, second.get(5, TimeUnit.SECONDS)}).containsExactlyInAnyOrder(1, -1);
            String winner = firstResult == 1 ? "first" : "second";
            String loser = firstResult == 1 ? "second" : "first";

            passwords.release(token, loser);
            assertThat(passwords.complete(token, loser)).isFalse();
            assertThat(passwords.complete(token, winner)).isTrue();
            assertThat(passwords.claim(token, PasswordPurpose.EXPIRED, winner)).isZero();
        }
    }
}
