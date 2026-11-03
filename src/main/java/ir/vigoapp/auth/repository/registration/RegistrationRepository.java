package ir.vigoapp.auth.repository.registration;

import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.model.registration.RegistrationChallenge;
import ir.vigoapp.auth.model.registration.RegistrationGrant;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** Registration keys share a cluster slot and never overlap login challenge keys. */
@Repository
@RequiredArgsConstructor
public class RegistrationRepository {
    private static final String PREFIX = "auth:registration:{registration}:";
    private static final DefaultRedisScript<Long> CREATE = script("create.lua");
    private static final DefaultRedisScript<Long> VERIFY = script("verify.lua");
    private static final DefaultRedisScript<Long> GRANT = script("grant.lua");
    private final StringRedisTemplate redis;
    private final AuthProperties properties;

    public void create(RegistrationChallenge challenge, String code) {
        long result = execute(CREATE, List.of(challengeKey(challenge.token()), PREFIX + "latest:" + challenge.identifier()),
                Long.toString(properties.getOtpTtl().toMillis()), challenge.identifier(), challenge.channel().name(),
                code, Long.toString(challenge.expiresAt().toEpochMilli()));
        if (result != 1) throw new IllegalStateException("Redis did not create the registration challenge");
    }

    public Optional<RegistrationChallenge> findChallenge(String token) {
        var values = redis.<String, String>opsForHash().entries(challengeKey(token));
        if (values.isEmpty()) return Optional.empty();
        return Optional.of(RegistrationChallenge.builder().token(token).identifier(values.get("identifier"))
                .channel(OtpChannel.valueOf(values.get("channel")))
                .expiresAt(Instant.ofEpochMilli(Long.parseLong(values.get("expiresAt"))))
                .failedAttempts(Integer.parseInt(values.get("failedAttempts"))).build());
    }

    /** 1 = verified; 0 = unavailable; negative = incorrect code, with the attempt count as magnitude. */
    public int verify(String token, String code, String registrationToken, Instant now) {
        return Math.toIntExact(execute(VERIFY, List.of(challengeKey(token), grantKey(registrationToken)), code,
                Integer.toString(properties.getOtpMaxAttempts()), Long.toString(now.toEpochMilli()),
                Long.toString(properties.getRegistrationTokenTtl().toMillis()),
                Long.toString(now.plus(properties.getRegistrationTokenTtl()).toEpochMilli())));
    }

    public void deleteChallenge(String token) {
        redis.delete(challengeKey(token));
    }

    public Optional<RegistrationGrant> findGrant(String token) {
        var values = redis.<String, String>opsForHash().entries(grantKey(token));
        if (values.isEmpty()) return Optional.empty();
        return Optional.of(RegistrationGrant.builder().token(token).identifier(values.get("identifier"))
                .channel(OtpChannel.valueOf(values.get("channel")))
                .expiresAt(Instant.ofEpochMilli(Long.parseLong(values.get("expiresAt")))).state(values.get("state"))
                .build());
    }

    public boolean claim(String token, String owner, Instant now) {
        return transition(token, "claim", owner, Long.toString(now.toEpochMilli())) == 1;
    }

    public void release(String token, String owner) {
        transition(token, "release", owner, "");
    }

    public boolean complete(String token, String owner) {
        return transition(token, "complete", owner, "") == 1;
    }

    private long transition(String token, String operation, String owner, String value) {
        return execute(GRANT, List.of(grantKey(token)), operation, owner, value);
    }

    private long execute(DefaultRedisScript<Long> script, List<String> keys, String... args) {
        Long result = redis.execute(script, keys, (Object[]) args);
        if (result == null) throw new IllegalStateException("Redis returned no registration state result");
        return result;
    }

    private static String challengeKey(String token) { return PREFIX + "challenge:" + token; }
    private static String grantKey(String token) { return PREFIX + "grant:" + token; }

    private static DefaultRedisScript<Long> script(String name) {
        var script = new DefaultRedisScript<Long>();
        script.setLocation(new ClassPathResource("redis/registration/" + name));
        script.setResultType(Long.class);
        return script;
    }
}
