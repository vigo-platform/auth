package ir.vigoapp.auth.service;

import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.client.user.model.UserLoginInfo;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.login.LoginResponse;
import ir.vigoapp.auth.dto.login.OtpChallengeResponse;
import ir.vigoapp.auth.dto.login.PasswordLoginRequest;
import ir.vigoapp.auth.dto.login.VerifyLoginRequest;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChallenge;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.repository.OtpChallengeRepository;
import ir.vigoapp.auth.security.SecureTokens;
import ir.vigoapp.auth.security.login.AccountEligibility;
import ir.vigoapp.auth.security.login.LoginIdentifier;
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
    private final OtpChallengeRepository challenges;
    private final NotificationService notifications;
    private final SecureTokens tokens;
    private final PasswordEncoder passwords;
    private final AuthProperties properties;
    private final Clock clock;
    private final String dummyPasswordHash;

    public LoginService(UserGrpcClient users, AuthSettingService settings, SessionService sessions,
                        LoginProtectionService protection, OtpChallengeRepository challenges,
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
                    .addKeyValue("subject", protection.auditSubject(identifierKey)).addKeyValue("ip_address", client.ipAddress())
                    .log("Password verification could not use the stored credential format.");
            matches = false;
        }
        if (info == null || !matches || !AccountEligibility.canLogin(info.user())) {
            protection.failed(identifierKey, info == null ? null : info.user().userId());
            log.atWarn().addKeyValue("event", "login_rejected").addKeyValue("result", "FAILURE")
                    .addKeyValue("reason", info == null ? "account_not_found" : !matches ? "invalid_password" : "account_ineligible")
                    .addKeyValue("subject", protection.auditSubject(identifierKey)).addKeyValue("user_id", info == null ? null : info.user().userId())
                    .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                    .addKeyValue("device_id", client.deviceId()).log("Password login rejected.");
            throw AuthException.invalidCredentials();
        }
        var user = info.user();
        protection.requireUnlocked(identifierKey);
        protection.requireUnlocked(protection.accountKey(user.userId()));
        if (user.twoFactorEnabled() || properties.isPasswordOtpRequired()) {
            OtpChannel channel = settings.getCurrent().defaultOtpChannel();
            if (!AccountEligibility.canReceiveOtp(user, channel)) {
                log.atWarn().addKeyValue("event", "login_rejected").addKeyValue("result", "FAILURE")
                        .addKeyValue("reason", "otp_channel_unavailable").addKeyValue("user_id", user.userId())
                        .addKeyValue("auth_method", "PASSWORD_OTP").addKeyValue("channel", channel)
                        .addKeyValue("two_factor_enabled", user.twoFactorEnabled())
                        .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                        .addKeyValue("device_id", client.deviceId()).log("Required second factor has no eligible delivery channel.");
                throw AuthException.invalidCredentials();
            }
            protection.reserveIdentifierCooldown(identifierKey);
            long remainingMs = protection.reserveAccountCooldown(user.userId());
            if (remainingMs > 0) {
                throw new AuthException(HttpStatus.TOO_MANY_REQUESTS, "OTP_COOLDOWN",
                        "Please wait before requesting another verification code.",
                        "برای درخواست کد تأیید جدید کمی صبر کنید.", Math.max(1, (remainingMs + 999) / 1000));
            }
            log.atInfo().addKeyValue("event", "login_second_factor_required").addKeyValue("user_id", user.userId())
                    .addKeyValue("auth_method", "PASSWORD_OTP").addKeyValue("channel", channel)
                    .addKeyValue("two_factor_enabled", user.twoFactorEnabled())
                    .addKeyValue("password_otp_required", properties.isPasswordOtpRequired())
                    .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                    .addKeyValue("device_id", client.deviceId()).log("Password verified; a second factor is required.");
            return issueChallenge(user, identifierKey, channel, true, client);
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
        // Also hide 2FA enrollment: passwordless OTP cannot replace the password factor.
        String skipReason = null;
        if (info == null) skipReason = "account_not_found";
        else if (info.user().twoFactorEnabled()) skipReason = "password_verification_required";
        else if (!AccountEligibility.canReceiveOtp(info.user(), channel)) skipReason = "account_ineligible";
        else if (protection.isLocked(identifierKey) || protection.isLocked(protection.accountKey(info.user().userId()))) skipReason = "account_locked";
        else if (protection.reserveAccountCooldown(info.user().userId()) > 0) skipReason = "account_cooldown";
        if (skipReason != null) {
            log.atInfo().addKeyValue("event", "otp_request_accepted").addKeyValue("delivery", "skipped")
                    .addKeyValue("subject", protection.auditSubject(identifierKey)).addKeyValue("channel", channel).addKeyValue("reason", skipReason)
                    .addKeyValue("user_id", info == null ? null : info.user().userId())
                    .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                    .addKeyValue("device_id", client.deviceId()).log("OTP request accepted without challenge delivery.");
            return challengeResponse(tokens.randomToken(), channel);
        }
        return issueChallenge(info.user(), identifierKey, channel, false, client);
    }

    @Transactional(noRollbackFor = AuthException.class)
    public LoginResponse verify(VerifyLoginRequest request, ClientInfo client) {
        requireLoginEnabled();
        protection.checkIp(client);
        String token = request.mfaToken();
        var challenge = challenges.find(token).orElseThrow(AuthException::invalidOtp);
        var now = clock.instant();
        if (!challenge.isOpen(now)) {
            log.atWarn().addKeyValue("event", "otp_rejected").addKeyValue("result", "REJECTED")
                    .addKeyValue("user_id", challenge.userId()).addKeyValue("channel", challenge.channel())
                    .addKeyValue("auth_method", challenge.authMethod())
                    .addKeyValue("reason", challenge.expiresAt().isAfter(now) ? "challenge_not_open" : "challenge_expired")
                    .addKeyValue("ip_address", client.ipAddress()).log("OTP challenge is no longer available for verification.");
            throw AuthException.invalidOtp();
        }
        protection.requireUnlocked(challenge.identifierKey());
        protection.requireUnlocked(protection.accountKey(challenge.userId()));
        if (!request.otp().equals(challenge.code())) {
            int attempts = challenges.failed(token);
            if (attempts > 0) {
                protection.failed(challenge.identifierKey(), challenge.userId());
                log.atWarn().addKeyValue("event", "otp_verification_failed").addKeyValue("result", "FAILURE")
                        .addKeyValue("user_id", challenge.userId()).addKeyValue("attempts", attempts)
                        .addKeyValue("attempt_limit", properties.getOtpMaxAttempts()).addKeyValue("channel", challenge.channel())
                        .addKeyValue("auth_method", challenge.authMethod())
                        .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                        .addKeyValue("device_id", client.deviceId()).log("Incorrect OTP submitted.");
            }
            throw AuthException.invalidOtp();
        }
        String owner = tokens.randomToken();
        if (!challenges.claim(token, owner)) throw AuthException.invalidOtp();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                try {
                    // Unknown outcomes remain claimed. Release only after a confirmed database rollback.
                    if (status == STATUS_COMMITTED || status == STATUS_ROLLED_BACK) {
                        challenges.complete(token, owner, status == STATUS_COMMITTED);
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
        // Recheck enrollment: a previously issued passwordless OTP must not bypass newly enabled 2FA.
        if (user.twoFactorEnabled() && !challenge.passwordVerified()) {
            log.atWarn().addKeyValue("event", "otp_rejected").addKeyValue("result", "REJECTED")
                    .addKeyValue("reason", "password_verification_required").addKeyValue("user_id", user.userId())
                    .addKeyValue("auth_method", challenge.authMethod()).addKeyValue("channel", challenge.channel())
                    .addKeyValue("two_factor_enabled", true).addKeyValue("ip_address", client.ipAddress())
                    .addKeyValue("user_agent", client.userAgent()).addKeyValue("device_id", client.deviceId())
                    .log("OTP cannot complete two-factor login without prior password verification.");
            throw AuthException.invalidOtp();
        }
        now = clock.instant();
        if (!challenge.expiresAt().isAfter(now) || user.credentialVersion() != challenge.credentialVersion()
                || !AccountEligibility.canReceiveOtp(user, challenge.channel())
                || !challenge.destination().equals(AccountEligibility.destination(user, challenge.channel()))) {
            throw AuthException.invalidOtp();
        }
        protection.requireUnlocked(challenge.identifierKey());
        protection.requireUnlocked(protection.accountKey(user.userId()));
        var response = LoginResponse.authenticated(sessions.create(user, client));
        clearFailuresAfterCommit(challenge.identifierKey(), user.userId(), client, challenge.authMethod());
        return response;
    }

    private LoginResponse issueChallenge(UserAccount user, String identifierKey, OtpChannel channel,
                                          boolean passwordVerified, ClientInfo client) {
        var now = clock.instant();
        String token = tokens.randomToken();
        String code = tokens.otp();
        var challenge = OtpChallenge.builder()
                .token(token)
                .identifierKey(identifierKey)
                .destination(AccountEligibility.destination(user, channel))
                .userId(user.userId())
                .credentialVersion(user.credentialVersion())
                .code(code)
                .channel(channel)
                .expiresAt(now.plus(properties.getOtpTtl()))
                .failedAttempts(0)
                .state("OPEN")
                .passwordVerified(passwordVerified)
                .build();
        challenges.create(challenge, protection.accountKey(user.userId()));
        notifications.sendLoginOtp(user.userId(), channel, AccountEligibility.destination(user, channel), code);
        log.atInfo().addKeyValue("event", "otp_challenge_created").addKeyValue("user_id", user.userId())
                .addKeyValue("auth_method", passwordVerified ? "PASSWORD_OTP" : "OTP")
                .addKeyValue("two_factor_enabled", user.twoFactorEnabled())
                .addKeyValue("channel", channel).addKeyValue("expires_in_seconds", properties.getOtpTtl().toSeconds())
                .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                .addKeyValue("device_id", client.deviceId()).log("OTP challenge created.");
        return challengeResponse(token, channel);
    }

    private LoginResponse challengeResponse(String token, OtpChannel channel) {
        return LoginResponse.otpRequired(OtpChallengeResponse.builder()
                .mfaToken(token)
                .channel(channel)
                .expiresIn(properties.getOtpTtl().toSeconds())
                .resendAfter(properties.getOtpCooldown().toSeconds())
                .build());
    }

    private UserLoginInfo findLoginInfo(String identifier) {
        try {
            boolean email = identifier.contains("@");
            var info = email ? users.getLoginInfoByEmail(identifier) : users.getLoginInfoByPhone(identifier);
            boolean matches = LoginIdentifier.matches(identifier, email ? info.user().email() : info.user().phone());
            if (!matches) throw new UserClientException(UserClientException.Code.INVALID_RESPONSE,
                    email ? "GetUserLoginInfoByEmail" : "GetUserLoginInfoByPhone");
            return info;
        } catch (UserClientException exception) {
            if (exception.getCode() == UserClientException.Code.NOT_FOUND) return null;
            throw exception;
        }
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
