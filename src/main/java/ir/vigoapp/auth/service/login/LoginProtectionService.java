package ir.vigoapp.auth.service.login;

import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.security.SecureTokens;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class LoginProtectionService {
    private static final DefaultRedisScript<Long> REQUEST_LIMIT = script("request-limit.lua");
    private static final DefaultRedisScript<Long> FAILURE = script("login-failure.lua");
    private static final DefaultRedisScript<Long> LOCK = script("login-lock.lua");
    private static final DefaultRedisScript<Long> COOLDOWN = script("otp-cooldown.lua");
    private static final DefaultRedisScript<Long> SUCCESS = script("login-success.lua");
    private final StringRedisTemplate redis;
    private final AuthProperties properties;
    private final SecureTokens tokens;

    public String identifierKey(String identifier) {
        return "identifier:" + identifier;
    }

    public String accountKey(long userId) {
        return "account:" + userId;
    }

    /** Keep audit identifiers private; Redis keys themselves remain readable. */
    public String auditSubject(String key) {
        int separator = key.indexOf(':');
        return tokens.fingerprint(key.substring(0, separator), key.substring(separator + 1));
    }

    public void checkIp(ClientInfo client) {
        String key = "auth:ip:" + client.ipAddress();
        long remaining = execute(REQUEST_LIMIT, key, Integer.toString(properties.getIpMaxRequests()),
                Long.toString(properties.getIpWindow().toMillis()));
        if (remaining > 0) {
            log.atWarn().addKeyValue("event", "auth_rate_limited").addKeyValue("scope", "ip")
                    .addKeyValue("ip_address", client.ipAddress()).addKeyValue("retry_after_ms", remaining)
                    .log("Authentication request rate limit exceeded.");
            throw limited("RATE_LIMITED", remaining);
        }
    }

    public boolean isLocked(String key) {
        return lockRemaining(key) > 0;
    }

    public void requireUnlocked(String key) {
        long remaining = lockRemaining(key);
        if (remaining > 0) {
            log.atWarn().addKeyValue("event", "login_blocked").addKeyValue("subject", auditSubject(key))
                    .addKeyValue("retry_after_ms", remaining).log("Login temporarily blocked by the failure limit.");
            throw limited("LOGIN_TEMPORARILY_LOCKED", remaining);
        }
    }

    public void failed(String identifierKey, Long userId) {
        recordFailure(identifierKey);
        if (userId != null) recordFailure(accountKey(userId));
    }

    public void clearFailures(String identifierKey, long userId) {
        execute(SUCCESS, "auth:failure:" + identifierKey);
        execute(SUCCESS, "auth:failure:" + accountKey(userId));
    }

    public void reserveIdentifierCooldown(String identifierKey) {
        long remaining = reserveCooldown(identifierKey);
        if (remaining > 0) throw limited("OTP_COOLDOWN", remaining);
    }

    public boolean reserveAccountCooldown(long userId) {
        return reserveCooldown(accountKey(userId)) == 0;
    }

    private long reserveCooldown(String key) {
        return execute(COOLDOWN, "auth:otp-cooldown:" + key, Long.toString(properties.getOtpCooldown().toMillis()));
    }

    private long lockRemaining(String key) {
        return execute(LOCK, "auth:failure:" + key);
    }

    private void recordFailure(String key) {
        long remaining = execute(FAILURE, "auth:failure:" + key,
                Integer.toString(properties.getMaxFailedAttempts()), Long.toString(properties.getFailureWindow().toMillis()),
                Long.toString(properties.getLockDuration().toMillis()), Long.toString(properties.getMaxLockDuration().toMillis()));
        log.atWarn().addKeyValue("event", "login_failure").addKeyValue("subject", auditSubject(key))
                .addKeyValue("lock_ms", remaining).log("Failed authentication attempt counted.");
    }

    private long execute(DefaultRedisScript<Long> script, String key, String... args) {
        Long result = redis.execute(script, List.of(key), (Object[]) args);
        if (result == null) throw new IllegalStateException("Redis returned no authentication policy result");
        return result;
    }

    private static AuthException limited(String code, long remainingMs) {
        long seconds = Math.max(1, (remainingMs + 999) / 1000);
        return new AuthException(HttpStatus.TOO_MANY_REQUESTS, code,
                "Too many attempts. Please try again later.", "تعداد درخواست‌ها بیش از حد مجاز است. کمی بعد دوباره تلاش کنید.", seconds);
    }

    private static DefaultRedisScript<Long> script(String name) {
        var script = new DefaultRedisScript<Long>();
        script.setLocation(new ClassPathResource("redis/" + name));
        script.setResultType(Long.class);
        return script;
    }
}
