package ir.vigoapp.auth.service;

import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.client.user.model.UserLoginInfo;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.dto.login.*;
import ir.vigoapp.auth.entity.OtpChannel;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.security.SecureTokens;
import ir.vigoapp.auth.service.login.*;
import ir.vigoapp.auth.service.notification.NotificationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.nio.charset.StandardCharsets;
import java.time.Clock;

@Service
@Slf4j
public class LoginService {
    private final UserGrpcClient users;
    private final AuthSettingService settings;
    private final SessionService sessions;
    private final LoginProtectionService protection;
    private final OtpChallengeStore challenges;
    private final NotificationService notifications;
    private final SecureTokens tokens;
    private final PasswordEncoder passwords;
    private final AuthProperties properties;
    private final Clock clock;
    private final String dummyPasswordHash;

    public LoginService(UserGrpcClient users, AuthSettingService settings, SessionService sessions,
                        LoginProtectionService protection, OtpChallengeStore challenges,
                        NotificationService notifications, SecureTokens tokens, PasswordEncoder passwords,
                        AuthProperties properties, Clock clock) {
        this.users = users;
        this.settings = settings;
        this.sessions = sessions;
        this.protection = protection;
        this.challenges = challenges;
        this.notifications = notifications;
        this.tokens = tokens;
        this.passwords = passwords;
        this.properties = properties;
        this.clock = clock;
        dummyPasswordHash = passwords.encode(tokens.randomToken());
    }

    @Transactional
    public LoginResponse loginWithPassword(PasswordLoginRequest request, ClientInfo client) {
        requireLoginEnabled();
        protection.checkIp(client);
        String identifier = LoginIdentifier.normalize(request.identifier());
        String identifierKey = protection.identifierKey(identifier);
        protection.requireUnlocked(identifierKey);
        if (request.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "INVALID_PASSWORD_LENGTH",
                    "Password must not exceed 72 UTF-8 bytes.", "طول رمز عبور نباید بیش از ۷۲ بایت باشد.");
        }
        UserLoginInfo info = findLoginInfo(identifier);
        if (info != null) protection.requireUnlocked(protection.accountKey(info.user().userId()));
        boolean matches;
        try {
            matches = passwords.matches(request.password(), info == null ? dummyPasswordHash : info.passwordHash());
        } catch (IllegalArgumentException exception) {
            passwords.matches(request.password(), dummyPasswordHash);
            log.atWarn().addKeyValue("event", "login_rejected").addKeyValue("reason", "unsupported_password_hash")
                    .addKeyValue("subject", identifierKey).addKeyValue("ip_address", client.ipAddress())
                    .log("Password verification could not use the stored credential format.");
            matches = false;
        }
        if (info == null || !matches || !AccountEligibility.canLogin(info.user())) {
            protection.failed(identifierKey, info == null ? null : info.user().userId());
            log.atWarn().addKeyValue("event", "login_rejected").addKeyValue("result", "FAILURE")
                    .addKeyValue("reason", info == null ? "account_not_found" : !matches ? "invalid_password" : "account_ineligible")
                    .addKeyValue("subject", identifierKey).addKeyValue("user_id", info == null ? null : info.user().userId())
                    .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                    .addKeyValue("device_id", client.deviceId()).log("Password login rejected.");
            throw AuthException.invalidCredentials();
        }
        var user = info.user();
        protection.requireUnlocked(identifierKey);
        protection.requireUnlocked(protection.accountKey(user.userId()));
        if (properties.isPasswordOtpRequired()) {
            OtpChannel channel = settings.getCurrent().defaultOtpChannel();
            if (!AccountEligibility.canReceiveOtp(user, channel)) throw AuthException.invalidCredentials();
            protection.reserveIdentifierCooldown(identifierKey);
            if (!protection.reserveAccountCooldown(user.userId())) {
                throw new AuthException(HttpStatus.TOO_MANY_REQUESTS, "OTP_COOLDOWN",
                        "Please wait before requesting another verification code.",
                        "برای درخواست کد تأیید جدید کمی صبر کنید.", properties.getOtpCooldown().toSeconds());
            }
            return issueChallenge(user, identifierKey, channel, client);
        }
        var response = LoginResponse.authenticated(sessions.create(user, client));
        clearFailuresAfterCommit(identifierKey, user.userId(), client, "PASSWORD");
        return response;
    }

    public LoginResponse loginWithOtp(String input, OtpChannel channel, ClientInfo client) {
        requireLoginEnabled();
        protection.checkIp(client);
        String identifier = LoginIdentifier.normalize(input);
        String identifierKey = protection.identifierKey(identifier);
        protection.reserveIdentifierCooldown(identifierKey);
        UserLoginInfo info = findLoginInfo(identifier);
        // Give indistinguishable challenge responses for unknown, disabled, unverified and locked accounts.
        String skipReason = null;
        if (info == null) skipReason = "account_not_found";
        else if (!AccountEligibility.canReceiveOtp(info.user(), channel)) skipReason = "account_ineligible";
        else if (protection.isLocked(identifierKey) || protection.isLocked(protection.accountKey(info.user().userId()))) skipReason = "account_locked";
        else if (!protection.reserveAccountCooldown(info.user().userId())) skipReason = "account_cooldown";
        if (skipReason != null) {
            log.atInfo().addKeyValue("event", "otp_request_accepted").addKeyValue("delivery", "skipped")
                    .addKeyValue("subject", identifierKey).addKeyValue("channel", channel).addKeyValue("reason", skipReason)
                    .addKeyValue("user_id", info == null ? null : info.user().userId())
                    .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                    .addKeyValue("device_id", client.deviceId()).log("OTP request accepted without challenge delivery.");
            return challengeResponse(tokens.randomToken(), channel);
        }
        return issueChallenge(info.user(), identifierKey, channel, client);
    }

    @Transactional(noRollbackFor = AuthException.class)
    public LoginResponse verify(VerifyLoginRequest request, ClientInfo client) {
        requireLoginEnabled();
        protection.checkIp(client);
        String hash = tokens.hash(request.mfaToken());
        var challenge = challenges.find(hash).orElseThrow(AuthException::invalidOtp);
        var now = clock.instant();
        if (!challenge.isOpen(now)) {
            log.atWarn().addKeyValue("event", "otp_rejected").addKeyValue("result", "REJECTED")
                    .addKeyValue("user_id", challenge.userId()).addKeyValue("channel", challenge.channel())
                    .addKeyValue("reason", challenge.expiresAt().isAfter(now) ? "challenge_not_open" : "challenge_expired")
                    .addKeyValue("ip_address", client.ipAddress()).log("OTP challenge is no longer available for verification.");
            throw AuthException.invalidOtp();
        }
        protection.requireUnlocked(challenge.identifierKey());
        protection.requireUnlocked(protection.accountKey(challenge.userId()));
        if (!tokens.matchesOtp(hash, request.otp(), challenge.codeHash())) {
            int attempts = challenges.failed(hash);
            if (attempts > 0) {
                protection.failed(challenge.identifierKey(), challenge.userId());
                log.atWarn().addKeyValue("event", "otp_verification_failed").addKeyValue("result", "FAILURE")
                        .addKeyValue("user_id", challenge.userId()).addKeyValue("attempts", attempts)
                        .addKeyValue("attempt_limit", properties.getOtpMaxAttempts()).addKeyValue("channel", challenge.channel())
                        .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                        .addKeyValue("device_id", client.deviceId()).log("Incorrect OTP submitted.");
            }
            throw AuthException.invalidOtp();
        }
        String owner = tokens.randomToken();
        if (!challenges.claim(hash, owner)) throw AuthException.invalidOtp();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                try {
                    // Unknown outcomes remain claimed. Release only after a confirmed database rollback.
                    if (status == STATUS_COMMITTED || status == STATUS_ROLLED_BACK) {
                        challenges.complete(hash, owner, status == STATUS_COMMITTED);
                    }
                } catch (RuntimeException exception) {
                    log.atWarn().addKeyValue("event", "otp_completion_failed").addKeyValue("user_id", challenge.userId())
                            .addKeyValue("reason", exception.getClass().getSimpleName()).addKeyValue("ip_address", client.ipAddress())
                            .log("OTP transaction completion could not update Redis.");
                }
            }
        });
        UserAccount user;
        try {
            user = users.getUserById(challenge.userId());
        } catch (UserClientException exception) {
            if (exception.getCode() != UserClientException.Code.NOT_FOUND) throw exception;
            throw AuthException.invalidOtp();
        }
        if (user.userId() != challenge.userId()) {
            throw new UserClientException(UserClientException.Code.INVALID_RESPONSE, "GetUserById");
        }
        now = clock.instant();
        if (!challenge.expiresAt().isAfter(now) || user.credentialVersion() != challenge.credentialVersion()
                || !AccountEligibility.canReceiveOtp(user, challenge.channel())
                || !challenge.destinationKey().equals(destinationKey(user, challenge.channel()))) {
            throw AuthException.invalidOtp();
        }
        protection.requireUnlocked(challenge.identifierKey());
        protection.requireUnlocked(protection.accountKey(user.userId()));
        var response = LoginResponse.authenticated(sessions.create(user, client));
        clearFailuresAfterCommit(challenge.identifierKey(), user.userId(), client, "OTP");
        return response;
    }

    private LoginResponse issueChallenge(UserAccount user, String identifierKey, OtpChannel channel, ClientInfo client) {
        var now = clock.instant();
        String token = tokens.randomToken();
        String hash = tokens.hash(token);
        String code = tokens.otp();
        challenges.create(new OtpChallenge(hash, identifierKey, destinationKey(user, channel), user.userId(), user.credentialVersion(),
                tokens.fingerprint("login-otp", hash + ":" + code), channel, now.plus(properties.getOtpTtl()), 0, "OPEN"),
                protection.accountKey(user.userId()));
        notifications.sendLoginOtp(user.userId(), channel, AccountEligibility.destination(user, channel), code);
        log.atInfo().addKeyValue("event", "otp_challenge_created").addKeyValue("user_id", user.userId())
                .addKeyValue("channel", channel).addKeyValue("expires_in_seconds", properties.getOtpTtl().toSeconds())
                .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                .addKeyValue("device_id", client.deviceId()).log("OTP challenge created.");
        return challengeResponse(token, channel);
    }

    private LoginResponse challengeResponse(String token, OtpChannel channel) {
        return LoginResponse.otpRequired(new OtpChallengeResponse(token, channel,
                properties.getOtpTtl().toSeconds(), properties.getOtpCooldown().toSeconds()));
    }

    private UserLoginInfo findLoginInfo(String identifier) {
        try {
            boolean email = identifier.contains("@");
            var info = email ? users.getLoginInfoByEmail(identifier) : users.getLoginInfoByPhone(identifier);
            boolean matches = email ? identifier.equalsIgnoreCase(info.user().email()) : identifier.equals(info.user().phone());
            if (!matches) throw new UserClientException(UserClientException.Code.INVALID_RESPONSE,
                    email ? "GetUserLoginInfoByEmail" : "GetUserLoginInfoByPhone");
            return info;
        } catch (UserClientException exception) {
            if (exception.getCode() == UserClientException.Code.NOT_FOUND) return null;
            throw exception;
        }
    }

    private String destinationKey(UserAccount user, OtpChannel channel) {
        return tokens.fingerprint("otp-destination", channel.name() + ":" + AccountEligibility.destination(user, channel));
    }

    private void requireLoginEnabled() {
        if (!settings.getCurrent().loginEnabled()) {
            throw new AuthException(HttpStatus.SERVICE_UNAVAILABLE, "LOGIN_DISABLED",
                    "Login is temporarily disabled.", "ورود موقتاً غیرفعال است.");
        }
    }

    private void clearFailuresAfterCommit(String identifierKey, long userId, ClientInfo client, String authMethod) {
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                log.atInfo().addKeyValue("event", "login_success").addKeyValue("result", "SUCCESS")
                        .addKeyValue("auth_method", authMethod).addKeyValue("user_id", userId)
                        .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                        .addKeyValue("device_id", client.deviceId()).log("User logged in successfully.");
                try {
                    protection.clearFailures(identifierKey, userId);
                } catch (DataAccessException exception) {
                    // The login is already committed; never lose the response because cleanup failed.
                    log.atWarn().addKeyValue("event", "login_counter_cleanup_failed").addKeyValue("user_id", userId)
                            .addKeyValue("ip_address", client.ipAddress()).addKeyValue("reason", exception.getClass().getSimpleName())
                            .log("Committed login could not clear its failure counters.");
                }
            }
        });
    }
}
