package ir.vigoapp.auth.service.login;

import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.entity.OtpChannel;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OtpChallengeStore {
    private static final String PREFIX = "auth:otp:{login}:challenge:";
    private static final DefaultRedisScript<Long> CREATE = script("otp-create.lua");
    private static final DefaultRedisScript<Long> TRANSITION = script("otp-transition.lua");
    private final StringRedisTemplate redis;
    private final AuthProperties properties;

    public void create(OtpChallenge challenge, String accountKey) {
        Long result = redis.execute(CREATE,
                List.of(PREFIX + challenge.tokenHash(), "auth:otp:{login}:latest:" + accountKey),
                Long.toString(properties.getOtpTtl().toMillis()), challenge.identifierKey(), challenge.destinationKey(),
                Long.toString(challenge.userId()), Long.toString(challenge.credentialVersion()), challenge.codeHash(),
                challenge.channel().name(), Long.toString(challenge.expiresAt().toEpochMilli()));
        if (!Long.valueOf(1).equals(result)) throw new IllegalStateException("Redis did not create the login challenge");
    }

    public Optional<OtpChallenge> find(String tokenHash) {
        var values = redis.<String, String>opsForHash().entries(PREFIX + tokenHash);
        if (values.isEmpty()) return Optional.empty();
        return Optional.of(new OtpChallenge(tokenHash, values.get("identifierKey"), values.get("destinationKey"),
                Long.parseLong(values.get("userId")), Long.parseLong(values.get("credentialVersion")), values.get("codeHash"),
                OtpChannel.valueOf(values.get("channel")), Instant.ofEpochMilli(Long.parseLong(values.get("expiresAt"))),
                Integer.parseInt(values.get("failedAttempts")), values.get("state")));
    }

    public int failed(String tokenHash) {
        return Math.toIntExact(transition(tokenHash, "fail", ""));
    }

    public boolean claim(String tokenHash, String owner) {
        return transition(tokenHash, "claim", owner) == 1;
    }

    public void complete(String tokenHash, String owner, boolean committed) {
        transition(tokenHash, committed ? "complete" : "release", owner);
    }

    private long transition(String hash, String operation, String owner) {
        Long result = redis.execute(TRANSITION, List.of(PREFIX + hash), operation, owner,
                Integer.toString(properties.getOtpMaxAttempts()));
        if (result == null) throw new IllegalStateException("Redis returned no OTP state result");
        return result;
    }

    private static DefaultRedisScript<Long> script(String name) {
        var script = new DefaultRedisScript<Long>();
        script.setLocation(new ClassPathResource("redis/" + name));
        script.setResultType(Long.class);
        return script;
    }
}
