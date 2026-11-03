package ir.vigoapp.auth.repository.password;

import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.model.password.PasswordChallenge;
import ir.vigoapp.auth.model.password.PasswordGrant;
import ir.vigoapp.auth.model.password.PasswordPurpose;
import ir.vigoapp.auth.security.SecureTokens;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Repository;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Repository
@RequiredArgsConstructor
public class PasswordRepository {
    // Share the login slot for an atomic exchange of an existing claimed login OTP.
    private static final String PREFIX = "auth:password:{login}:";
    private static final String LOGIN_CHALLENGE_PREFIX = "auth:otp:{login}:challenge:";
    private static final DefaultRedisScript<Long> CREATE = script("create.lua");
    private static final DefaultRedisScript<Long> EXCHANGE = script("exchange.lua");
    private static final DefaultRedisScript<Long> EXCHANGE_LOGIN = script("exchange-login.lua");
    private static final DefaultRedisScript<Long> TRANSITION = script("transition.lua");
    private final StringRedisTemplate redis;
    private final AuthProperties properties;
    private final SecureTokens tokens;
    private final Clock clock;

    public void createGrant(String token, PasswordGrant grant) {
        if (execute(CREATE, List.of(grantKey(token)), createArgs(grant.expiresAt(), grantFields(grant))) != 1) {
            throw new IllegalStateException("Redis did not create the password grant");
        }
    }

    public Optional<PasswordGrant> findGrant(String token) {
        var values = redis.<String, String>opsForHash().entries(grantKey(token));
        if (values.isEmpty()) return Optional.empty();
        return Optional.of(PasswordGrant.builder()
                .purpose(PasswordPurpose.valueOf(values.get("purpose")))
                .userId(Long.parseLong(values.get("userId")))
                .credentialVersion(Long.parseLong(values.get("credentialVersion")))
                .sessionId(sessionId(values))
                .passwordVerified(Boolean.parseBoolean(values.get("passwordVerified")))
                .channel(channel(values.get("channel")))
                .destination(nullable(values.get("destination")))
                .otherChannel(channel(values.get("otherChannel")))
                .otherDestination(nullable(values.get("otherDestination")))
                .expiresAt(expiresAt(values))
                .state(values.get("state")).build());
    }

    public void createChallenge(String token, PasswordChallenge challenge, String code) {
        var keys = List.of(challengeKey(token), latestKey(challenge));
        if (execute(CREATE, keys, createArgs(challenge.expiresAt(), challengeFields(challenge, code))) != 1) {
            throw new IllegalStateException("Redis did not create the password challenge");
        }
    }

    public Optional<PasswordChallenge> findChallenge(String token) {
        var values = redis.<String, String>opsForHash().entries(challengeKey(token));
        if (values.isEmpty()) return Optional.empty();
        return Optional.of(PasswordChallenge.builder()
                .purpose(PasswordPurpose.valueOf(values.get("purpose")))
                .userId(Long.parseLong(values.get("userId")))
                .credentialVersion(Long.parseLong(values.get("credentialVersion")))
                .sessionId(sessionId(values))
                .identifierKey(values.get("identifierKey"))
                .channel(OtpChannel.valueOf(values.get("channel")))
                .destination(values.get("destination"))
                .previousChannel(channel(values.get("previousChannel")))
                .previousDestination(nullable(values.get("previousDestination")))
                .expiresAt(expiresAt(values)).build());
    }

    public void deleteChallenge(String token) {
        redis.delete(challengeKey(token));
    }

    /** Reject incorrect codes before looking up the account, leaving a correct code open for exchange. */
    public int checkCode(String token, PasswordPurpose purpose, String code) {
        return Math.toIntExact(execute(EXCHANGE, List.of(challengeKey(token)),
                List.of(purpose.name(), code, Integer.toString(properties.getOtpMaxAttempts()), millis(clock.instant()))));
    }

    /** 1 = exchanged; 0 = unavailable; negative = incorrect code with attempt count as magnitude. */
    public int verify(String token, PasswordPurpose purpose, String code, String grantToken, PasswordGrant grant) {
        return exchange(List.of(challengeKey(token), grantKey(grantToken)), purpose, code,
                grant.expiresAt(), grantFields(grant));
    }

    /** Advance a reset challenge to the second verified destination. */
    public int advance(String token, PasswordPurpose purpose, String code, String nextToken,
                       PasswordChallenge next, String nextCode) {
        return exchange(List.of(challengeKey(token), challengeKey(nextToken), latestKey(next)), purpose, code,
                next.expiresAt(), challengeFields(next, nextCode));
    }

    public boolean exchangeLoginOtp(String mfaToken, String owner, String grantToken, PasswordGrant grant) {
        var args = new ArrayList<>(List.of(owner, millis(clock.instant()), millis(grant.expiresAt())));
        args.addAll(grantFields(grant));
        return execute(EXCHANGE_LOGIN, List.of(LOGIN_CHALLENGE_PREFIX + mfaToken, grantKey(grantToken)), args) == 1;
    }

    /** 1 = acquired; -1 = another completion owns the claim; 0 = unavailable. */
    public int claim(String token, PasswordPurpose purpose, String owner) {
        return Math.toIntExact(execute(TRANSITION, List.of(grantKey(token)),
                List.of("claim", owner, millis(clock.instant()), purpose.name())));
    }

    public void release(String token, String owner) {
        execute(TRANSITION, List.of(grantKey(token)), List.of("release", owner));
    }

    public boolean complete(String token, String owner) {
        return execute(TRANSITION, List.of(grantKey(token)), List.of("complete", owner)) == 1;
    }

    private int exchange(List<String> keys, PasswordPurpose purpose, String code, Instant expiresAt, List<String> fields) {
        var args = new ArrayList<>(List.of(purpose.name(), code, Integer.toString(properties.getOtpMaxAttempts())));
        args.addAll(createArgs(expiresAt, fields));
        return Math.toIntExact(execute(EXCHANGE, keys, args));
    }

    private List<String> createArgs(Instant expiresAt, List<String> fields) {
        var args = new ArrayList<>(List.of(millis(clock.instant()), millis(expiresAt)));
        args.addAll(fields);
        return args;
    }

    private static List<String> grantFields(PasswordGrant grant) {
        return List.of("purpose", grant.purpose().name(), "userId", Long.toString(grant.userId()),
                "credentialVersion", Long.toString(grant.credentialVersion()), "sessionId", string(grant.sessionId()),
                "passwordVerified", Boolean.toString(grant.passwordVerified()), "channel", string(grant.channel()),
                "destination", string(grant.destination()), "otherChannel", string(grant.otherChannel()),
                "otherDestination", string(grant.otherDestination()), "expiresAt", millis(grant.expiresAt()),
                "state", "OPEN");
    }

    private static List<String> challengeFields(PasswordChallenge challenge, String code) {
        return List.of("purpose", challenge.purpose().name(), "userId", Long.toString(challenge.userId()),
                "credentialVersion", Long.toString(challenge.credentialVersion()),
                "sessionId", string(challenge.sessionId()), "identifierKey", challenge.identifierKey(),
                "channel", challenge.channel().name(), "destination", challenge.destination(),
                "previousChannel", string(challenge.previousChannel()),
                "previousDestination", string(challenge.previousDestination()), "code", code,
                "expiresAt", millis(challenge.expiresAt()), "failedAttempts", "0");
    }

    private long execute(DefaultRedisScript<Long> script, List<String> keys, List<String> args) {
        Long result = redis.execute(script, keys, args.toArray());
        if (result == null) throw new IllegalStateException("Redis returned no password state result");
        return result;
    }

    private String challengeKey(String token) {
        return PREFIX + "challenge:" + tokens.hash(token);
    }

    private String grantKey(String token) {
        return PREFIX + "grant:" + tokens.hash(token);
    }

    private static String latestKey(PasswordChallenge challenge) {
        return PREFIX + "latest:" + challenge.purpose().name() + ":" + challenge.userId();
    }

    private static Instant expiresAt(Map<String, String> values) {
        return Instant.ofEpochMilli(Long.parseLong(values.get("expiresAt")));
    }

    private static UUID sessionId(Map<String, String> values) {
        String value = nullable(values.get("sessionId"));
        return value == null ? null : UUID.fromString(value);
    }

    private static OtpChannel channel(String value) {
        return value == null || value.isEmpty() ? null : OtpChannel.valueOf(value);
    }

    private static String nullable(String value) {
        return value == null || value.isEmpty() ? null : value;
    }

    private static String string(Object value) {
        return value == null ? "" : value.toString();
    }

    private static String millis(Instant instant) {
        return Long.toString(instant.toEpochMilli());
    }

    private static DefaultRedisScript<Long> script(String name) {
        var script = new DefaultRedisScript<Long>();
        script.setLocation(new ClassPathResource("redis/password/" + name));
        script.setResultType(Long.class);
        return script;
    }
}
