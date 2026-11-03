package ir.vigoapp.auth.service;

import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.ChangePasswordCommand;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.client.user.model.UserLoginInfo;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.login.LoginResponse;
import ir.vigoapp.auth.dto.login.OtpChallengeResponse;
import ir.vigoapp.auth.dto.password.PasswordGrantResponse;
import ir.vigoapp.auth.dto.password.PasswordStepResponse;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChallenge;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.model.password.PasswordChallenge;
import ir.vigoapp.auth.model.password.PasswordGrant;
import ir.vigoapp.auth.model.password.PasswordPurpose;
import ir.vigoapp.auth.repository.AuthSessionRepository;
import ir.vigoapp.auth.repository.password.PasswordRepository;
import ir.vigoapp.auth.security.PasswordPolicy;
import ir.vigoapp.auth.security.SecureTokens;
import ir.vigoapp.auth.security.login.AccountEligibility;
import ir.vigoapp.auth.security.login.LoginIdentifier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.core.task.TaskRejectedException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Service
@Slf4j
public class PasswordLifecycleService {
    private final UserGrpcClient users;
    private final PasswordRepository repository;
    private final AuthSessionRepository sessions;
    private final SessionService sessionService;
    private final AuthProtectionService protection;
    private final AuthPolicyService policy;
    private final NotificationService notifications;
    private final PasswordEncoder passwords;
    private final SecureTokens tokens;
    private final AuthProperties properties;
    private final Clock clock;
    private final TaskExecutor recoveryExecutor;

    public PasswordLifecycleService(UserGrpcClient users, PasswordRepository repository, AuthSessionRepository sessions,
                                    SessionService sessionService, AuthProtectionService protection, AuthPolicyService policy,
                                    NotificationService notifications, PasswordEncoder passwords, SecureTokens tokens,
                                    AuthProperties properties, Clock clock,
                                    @Qualifier("passwordRecoveryExecutor") TaskExecutor recoveryExecutor) {
        this.users = users;
        this.repository = repository;
        this.sessions = sessions;
        this.sessionService = sessionService;
        this.protection = protection;
        this.policy = policy;
        this.notifications = notifications;
        this.passwords = passwords;
        this.tokens = tokens;
        this.properties = properties;
        this.clock = clock;
        this.recoveryExecutor = recoveryExecutor;
    }

    public PasswordGrantResponse issueExpired(UserAccount user, OtpChannel channel, String destination, boolean passwordVerified) {
        String token = tokens.randomToken();
        repository.createGrant(token, grant(PasswordPurpose.EXPIRED, user, null, passwordVerified, channel, destination));
        return changeGrantResponse(token);
    }

    public PasswordGrantResponse issueExpiredFromOtp(UserAccount user, OtpChallenge challenge, String owner) {
        String token = tokens.randomToken();
        var grant = grant(PasswordPurpose.EXPIRED, user, null, challenge.passwordVerified(), challenge.channel(), challenge.destination());
        if (!repository.exchangeLoginOtp(challenge.token(), owner, token, grant)) throw AuthException.invalidOtp();
        return changeGrantResponse(token);
    }

    public LoginResponse completeExpired(String token, String newPassword, ClientInfo client) {
        var update = updatePassword(PasswordPurpose.EXPIRED, null, token, newPassword, client);
        try {
            var user = users.getUserById(update.grant().userId());
            if (user.userId() == update.grant().userId() && user.credentialVersion() == update.version()
                    && AccountEligibility.canLogin(user) && isProofCurrent(update.grant(), user)) {
                return LoginResponse.authenticated(sessionService.create(user, client));
            }
        } catch (RuntimeException exception) {
            logFailure("password_updated_session_unavailable", update.grant().userId(), exception);
        }
        return LoginResponse.passwordUpdatedLoginRequired();
    }

    public PasswordStepResponse initiateChange(Jwt jwt, String currentPassword, ClientInfo client) {
        protection.checkIp(client);
        PasswordPolicy.requireBcryptLength(currentPassword);
        var session = requireSession(jwt);
        String accountKey = protection.accountKey(session.userId());
        protection.requireUnlocked(accountKey);
        var info = loginInfo(session.userId());
        requireCurrentSession(session, info.user());
        if (!matches(currentPassword, info.passwordHash())) {
            protection.failed(accountKey, null);
            throw AuthException.invalidCredentials();
        }
        protection.requireUnlocked(accountKey);
        if (!requiresPasswordOtp(info.user())) {
            String token = tokens.randomToken();
            repository.createGrant(token, grant(PasswordPurpose.CHANGE, info.user(), session.id(), true, null, null));
            return PasswordStepResponse.changeRequired(changeGrantResponse(token));
        }
        OtpChannel channel = policy.requireDefaultPasswordOtpChannel();
        String destination = AccountEligibility.destination(info.user(), channel);
        if (!destinationIsCurrent(info.user(), channel, destination)) throw AuthException.invalidCredentials();
        String cooldownKey = "password-change:" + accountKey;
        protection.reserveIdentifierCooldown(cooldownKey);
        String token = tokens.randomToken();
        var challenge = PasswordChallenge.builder().purpose(PasswordPurpose.CHANGE).userId(session.userId())
                .credentialVersion(session.version()).sessionId(session.id()).identifierKey(accountKey)
                .channel(channel).destination(destination).expiresAt(clock.instant().plus(properties.getOtpTtl())).build();
        String code = tokens.otp();
        repository.createChallenge(token, challenge, code);
        deliver(token, challenge, code);
        return otpResponse(token, channel);
    }

    public PasswordStepResponse verifyChange(Jwt jwt, String token, String otp, ClientInfo client) {
        protection.checkIp(client);
        var session = requireSession(jwt);
        var challenge = findChallenge(token, PasswordPurpose.CHANGE);
        if (!session.id().equals(challenge.sessionId()) || session.userId() != challenge.userId()) throw AuthException.invalidOtp();
        protection.requireUnlocked(challenge.identifierKey());
        verifyResult(challenge, repository.checkCode(token, PasswordPurpose.CHANGE, otp));
        var user = challengeUser(session.userId());
        requireCurrentSession(session, user);
        requireCurrentChallenge(challenge, user);
        String grantToken = tokens.randomToken();
        var grant = grant(PasswordPurpose.CHANGE, user, session.id(), true, challenge.channel(), challenge.destination());
        verifyResult(challenge, repository.verify(token, PasswordPurpose.CHANGE, otp, grantToken, grant));
        return PasswordStepResponse.changeRequired(changeGrantResponse(grantToken));
    }

    public PasswordStepResponse completeChange(Jwt jwt, String token, String newPassword, ClientInfo client) {
        updatePassword(PasswordPurpose.CHANGE, jwt, token, newPassword, client);
        return PasswordStepResponse.updatedLoginRequired();
    }

    public PasswordStepResponse initiateReset(String input, ClientInfo client) {
        protection.checkIp(client);
        String identifier = LoginIdentifier.normalize(input);
        String key = "password-reset:" + protection.identifierKey(identifier);
        protection.reserveIdentifierCooldown(key);
        OtpChannel channel = identifier.contains("@") ? OtpChannel.EMAIL : OtpChannel.SMS;
        policy.requirePasswordOtpEnabled(channel);
        String token = tokens.randomToken();
        var expiresAt = clock.instant().plus(properties.getOtpTtl());
        try {
            recoveryExecutor.execute(() -> prepareRecovery(identifier, channel, token, key, expiresAt));
        } catch (TaskRejectedException exception) {
            throw new AuthException(HttpStatus.SERVICE_UNAVAILABLE, "AUTH_SERVICE_UNAVAILABLE",
                    "Password recovery is temporarily unavailable.", "بازیابی رمز عبور موقتاً در دسترس نیست.");
        }
        return otpResponse(token, channel);
    }

    private void prepareRecovery(String identifier, OtpChannel channel, String token, String key, Instant expiresAt) {
        try {
            if (!expiresAt.isAfter(clock.instant()) || protection.isLocked(key)) return;
            var user = findRecoveryAccount(identifier, channel);
            if (user == null || protection.isLocked(recoveryAccountKey(user.userId()))) return;
            String destination = AccountEligibility.destination(user, channel);
            if (!LoginIdentifier.matches(identifier, destination) || !destinationIsCurrent(user, channel, destination)) return;
            if (user.twoFactorEnabled() && !canSendSecondRecoveryCode(user, channel)) return;
            policy.requirePasswordOtpEnabled(channel);
            if (!expiresAt.isAfter(clock.instant()) || protection.reserveCooldown(recoveryAccountKey(user.userId())) > 0) return;
            var challenge = PasswordChallenge.builder().purpose(PasswordPurpose.RESET).userId(user.userId())
                    .credentialVersion(user.credentialVersion()).identifierKey(key).channel(channel)
                    .destination(destination).expiresAt(expiresAt).build();
            String code = tokens.otp();
            repository.createChallenge(token, challenge, code);
            deliver(token, challenge, code);
        } catch (RuntimeException exception) {
            logFailure("password_reset_delivery_unavailable", null, exception);
        }
    }

    public PasswordStepResponse verifyReset(String token, String otp, ClientInfo client) {
        protection.checkIp(client);
        var challenge = findChallenge(token, PasswordPurpose.RESET);
        protection.requireUnlocked(challenge.identifierKey());
        protection.requireUnlocked(recoveryAccountKey(challenge.userId()));
        verifyResult(challenge, repository.checkCode(token, PasswordPurpose.RESET, otp));
        var user = challengeUser(challenge.userId());
        requireCurrentChallenge(challenge, user);
        if (user.twoFactorEnabled() && challenge.previousChannel() == null) {
            return advanceRecovery(token, otp, challenge, user);
        }
        String grantToken = tokens.randomToken();
        var grant = PasswordGrant.builder().purpose(PasswordPurpose.RESET).userId(user.userId())
                .credentialVersion(user.credentialVersion()).channel(challenge.channel()).destination(challenge.destination())
                .otherChannel(challenge.previousChannel()).otherDestination(challenge.previousDestination())
                .expiresAt(clock.instant().plus(properties.getPasswordGrantTtl())).build();
        verifyResult(challenge, repository.verify(token, PasswordPurpose.RESET, otp, grantToken, grant));
        return PasswordStepResponse.resetRequired(grantToken, properties.getPasswordGrantTtl().toSeconds());
    }

    public PasswordStepResponse completeReset(String token, String newPassword, ClientInfo client) {
        var update = updatePassword(PasswordPurpose.RESET, null, token, newPassword, client);
        try {
            notifications.sendPasswordResetNotice(update.grant().userId());
        } catch (RuntimeException exception) {
            logFailure("password_reset_notice_failed", update.grant().userId(), exception);
        }
        return PasswordStepResponse.updatedLoginRequired();
    }

    private PasswordStepResponse advanceRecovery(String token, String otp, PasswordChallenge challenge, UserAccount user) {
        OtpChannel channel = otherRecoveryChannel(challenge.channel());
        String destination = AccountEligibility.destination(user, channel);
        if (!destinationIsCurrent(user, channel, destination)) throw AuthException.invalidOtp();
        policy.requirePasswordOtpEnabled(channel);
        String nextToken = tokens.randomToken();
        String nextCode;
        do {
            nextCode = tokens.otp();
        } while (nextCode.equals(otp));
        var next = PasswordChallenge.builder().purpose(PasswordPurpose.RESET).userId(user.userId())
                .credentialVersion(user.credentialVersion()).identifierKey(challenge.identifierKey())
                .channel(channel).destination(destination).previousChannel(challenge.channel())
                .previousDestination(challenge.destination()).expiresAt(clock.instant().plus(properties.getOtpTtl())).build();
        verifyResult(challenge, repository.advance(token, PasswordPurpose.RESET, otp, nextToken, next, nextCode));
        deliver(nextToken, next, nextCode);
        return otpResponse(nextToken, channel);
    }

    private PasswordUpdate updatePassword(PasswordPurpose purpose, Jwt jwt, String token, String newPassword, ClientInfo client) {
        protection.checkIp(client);
        var grant = repository.findGrant(token).filter(value -> value.purpose() == purpose
                && value.expiresAt().isAfter(clock.instant())).orElseThrow(PasswordLifecycleService::invalidGrant);
        var session = purpose == PasswordPurpose.CHANGE ? requireSession(jwt) : null;
        if (session != null && (grant.userId() != session.userId() || !session.id().equals(grant.sessionId()))) throw invalidGrant();
        if (grant.isClaimed()) throw staleOrClaimed();
        if (!grant.isOpen()) throw invalidGrant();
        PasswordPolicy.validateNewPassword(newPassword);

        var info = loginInfo(grant.userId());
        var user = info.user();
        if (user.credentialVersion() != grant.credentialVersion()) throw staleOrClaimed();
        if (session != null) requireCurrentSession(session, user);
        if (!AccountEligibility.isActive(user) || !isProofCurrent(grant, user)) throw invalidGrant();
        if (purpose == PasswordPurpose.EXPIRED && !user.credentialsExpired()) throw invalidGrant();
        if (purpose == PasswordPurpose.RESET) protection.requireUnlocked(recoveryAccountKey(user.userId()));
        else protection.requireUnlocked(protection.accountKey(user.userId()));
        if (matches(newPassword, info.passwordHash())) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "PASSWORD_REUSED",
                    "Choose a password different from your current password.", "رمز جدید باید با رمز فعلی متفاوت باشد.");
        }
        String encoded = passwords.encode(newPassword);
        String owner = tokens.randomToken();
        int result = repository.claim(token, purpose, owner);
        if (result == -1) throw staleOrClaimed();
        if (result != 1) throw invalidGrant();

        try {
            if (session != null) requireSession(jwt);
            if (!isProofCurrent(grant, user) || !grant.expiresAt().isAfter(clock.instant())) throw invalidGrant();
        } catch (RuntimeException exception) {
            try {
                repository.release(token, owner);
            } catch (RuntimeException cleanupFailure) {
                logFailure("password_grant_release_failed", user.userId(), cleanupFailure);
            }
            throw exception;
        }

        long version;
        try {
            version = users.changeUserPassword(new ChangePasswordCommand(user.userId(), encoded, grant.credentialVersion()));
        } catch (UserClientException exception) {
            if (exception.getCode() == UserClientException.Code.CONFLICT) {
                spend(token, owner, user.userId());
                throw staleOrClaimed();
            }
            if (exception.getCode() == UserClientException.Code.NOT_FOUND
                    || exception.getCode() == UserClientException.Code.PERMISSION_DENIED
                    || exception.getCode() == UserClientException.Code.FAILED_PRECONDITION) {
                spend(token, owner, user.userId());
                throw invalidGrant();
            }
            // The RPC has no idempotency key. Retain the claim when commit is uncertain.
            logFailure("password_update_outcome_unknown", user.userId(), exception);
            throw new AuthException(HttpStatus.SERVICE_UNAVAILABLE, "PASSWORD_UPDATE_OUTCOME_UNKNOWN",
                    "The update could not be confirmed. Try signing in with your new password or restart the flow.",
                    "نتیجهٔ تغییر رمز مشخص نیست. با رمز جدید وارد شوید یا فرایند را از ابتدا شروع کنید.");
        }
        spend(token, owner, user.userId());
        try {
            sessionService.revokeOlderCredentials(user.userId(), version);
        } catch (RuntimeException exception) {
            logFailure("password_update_session_revocation_failed", user.userId(), exception);
        }
        log.atInfo().addKeyValue("event", "password_updated").addKeyValue("user_id", user.userId())
                .addKeyValue("purpose", purpose).log("User confirmed the password update.");
        return new PasswordUpdate(grant, version);
    }

    private boolean isProofCurrent(PasswordGrant grant, UserAccount user) {
        if (grant.purpose() == PasswordPurpose.EXPIRED) {
            policy.requireLoginEnabled();
            if (grant.channel() != null) policy.requireLoginOtpEnabled(grant.channel());
            if ((user.twoFactorEnabled() && !grant.passwordVerified())
                    || (grant.passwordVerified() && requiresPasswordOtp(user) && grant.channel() == null)) return false;
        } else {
            if (grant.channel() != null) policy.requirePasswordOtpEnabled(grant.channel());
            if (grant.otherChannel() != null) policy.requirePasswordOtpEnabled(grant.otherChannel());
            if (grant.purpose() == PasswordPurpose.CHANGE && requiresPasswordOtp(user) && grant.channel() == null) return false;
            if (grant.purpose() == PasswordPurpose.RESET && user.twoFactorEnabled() && grant.otherChannel() == null) return false;
        }
        return (grant.channel() == null || destinationIsCurrent(user, grant.channel(), grant.destination()))
                && (grant.otherChannel() == null || destinationIsCurrent(user, grant.otherChannel(), grant.otherDestination()));
    }

    private SessionIdentity requireSession(Jwt jwt) {
        if (jwt == null || jwt.getExpiresAt() == null || !jwt.getExpiresAt().isAfter(clock.instant())) throw AuthException.invalidCredentials();
        UUID id = UUID.fromString(jwt.getClaimAsString("sid"));
        long userId = Long.parseLong(jwt.getSubject());
        Number version = jwt.getClaim("credential_version");
        var session = sessions.findById(id).filter(value -> value.isActive(clock.instant()) && value.getUserId() == userId
                && version != null && value.getCredentialVersion() == version.longValue()).orElseThrow(AuthException::invalidCredentials);
        return new SessionIdentity(id, userId, session.getCredentialVersion());
    }

    private void requireCurrentSession(SessionIdentity session, UserAccount user) {
        if (user.userId() != session.userId() || user.credentialVersion() != session.version()
                || !AccountEligibility.canLogin(user)) throw AuthException.invalidCredentials();
    }

    private PasswordChallenge findChallenge(String token, PasswordPurpose purpose) {
        return repository.findChallenge(token).filter(value -> value.purpose() == purpose
                && value.expiresAt().isAfter(clock.instant())).orElseThrow(AuthException::invalidOtp);
    }

    private void requireCurrentChallenge(PasswordChallenge challenge, UserAccount user) {
        policy.requirePasswordOtpEnabled(challenge.channel());
        if (challenge.previousChannel() != null) policy.requirePasswordOtpEnabled(challenge.previousChannel());
        if (user.userId() != challenge.userId() || user.credentialVersion() != challenge.credentialVersion()
                || !destinationIsCurrent(user, challenge.channel(), challenge.destination())
                || (challenge.previousChannel() != null
                    && !destinationIsCurrent(user, challenge.previousChannel(), challenge.previousDestination()))) {
            throw AuthException.invalidOtp();
        }
    }

    private boolean canSendSecondRecoveryCode(UserAccount user, OtpChannel first) {
        OtpChannel second = otherRecoveryChannel(first);
        if (!destinationIsCurrent(user, second, AccountEligibility.destination(user, second))) return false;
        policy.requirePasswordOtpEnabled(second);
        return true;
    }

    private static OtpChannel otherRecoveryChannel(OtpChannel channel) {
        return channel == OtpChannel.EMAIL ? OtpChannel.SMS : OtpChannel.EMAIL;
    }

    private static boolean destinationIsCurrent(UserAccount user, OtpChannel channel, String destination) {
        return AccountEligibility.canReceiveOtp(user, channel)
                && Objects.equals(destination, AccountEligibility.destination(user, channel));
    }

    private UserAccount findRecoveryAccount(String identifier, OtpChannel channel) {
        try {
            return (channel == OtpChannel.EMAIL ? users.getLoginInfoByEmail(identifier) : users.getLoginInfoByPhone(identifier)).user();
        } catch (UserClientException exception) {
            if (exception.getCode() == UserClientException.Code.NOT_FOUND) return null;
            throw exception;
        }
    }

    private UserAccount challengeUser(long userId) {
        try {
            return users.getUserById(userId);
        } catch (UserClientException exception) {
            if (exception.getCode() == UserClientException.Code.NOT_FOUND) throw AuthException.invalidOtp();
            throw exception;
        }
    }

    private UserLoginInfo loginInfo(long userId) {
        try {
            var info = users.getLoginInfoById(userId);
            if (info.user().userId() != userId) throw new UserClientException(UserClientException.Code.INVALID_RESPONSE, "GetUserLoginInfoById");
            return info;
        } catch (UserClientException exception) {
            if (exception.getCode() == UserClientException.Code.NOT_FOUND) throw invalidGrant();
            throw exception;
        }
    }

    private boolean matches(String password, String hash) {
        try {
            return passwords.matches(password, hash);
        } catch (IllegalArgumentException exception) {
            throw new UserClientException(UserClientException.Code.INVALID_RESPONSE, "GetUserLoginInfoById");
        }
    }

    private void deliver(String token, PasswordChallenge challenge, String code) {
        try {
            if (challenge.purpose() == PasswordPurpose.RESET) {
                notifications.sendPasswordResetOtp(challenge.userId(), challenge.channel(), challenge.destination(), code);
            } else {
                notifications.sendPasswordChangeOtp(challenge.userId(), challenge.channel(), challenge.destination(), code);
            }
        } catch (RuntimeException exception) {
            try {
                repository.deleteChallenge(token);
            } catch (RuntimeException cleanupFailure) {
                logFailure("password_otp_cleanup_failed", challenge.userId(), cleanupFailure);
            }
            throw exception;
        }
    }

    private void verifyResult(PasswordChallenge challenge, int result) {
        if (result == 1) return;
        if (result < 0) {
            if (challenge.purpose() == PasswordPurpose.RESET) {
                protection.failed(challenge.identifierKey(), null);
                protection.failed(recoveryAccountKey(challenge.userId()), null);
            } else {
                protection.failed(challenge.identifierKey(), null);
            }
        }
        throw AuthException.invalidOtp();
    }

    private PasswordGrant grant(PasswordPurpose purpose, UserAccount user, UUID sessionId, boolean passwordVerified,
                                OtpChannel channel, String destination) {
        return PasswordGrant.builder().purpose(purpose).userId(user.userId()).credentialVersion(user.credentialVersion())
                .sessionId(sessionId).passwordVerified(passwordVerified).channel(channel).destination(destination)
                .expiresAt(clock.instant().plus(properties.getPasswordGrantTtl())).build();
    }

    private PasswordGrantResponse changeGrantResponse(String token) {
        return new PasswordGrantResponse(token, properties.getPasswordGrantTtl().toSeconds());
    }

    private PasswordStepResponse otpResponse(String token, OtpChannel channel) {
        return PasswordStepResponse.otpRequired(OtpChallengeResponse.builder().mfaToken(token).channel(channel)
                .expiresIn(properties.getOtpTtl().toSeconds()).resendAfter(properties.getOtpCooldown().toSeconds()).build());
    }

    private boolean requiresPasswordOtp(UserAccount user) {
        return user.twoFactorEnabled() || properties.isPasswordOtpRequired();
    }

    private String recoveryAccountKey(long userId) {
        return "password-reset:" + protection.accountKey(userId);
    }

    private void spend(String token, String owner, long userId) {
        try {
            repository.complete(token, owner);
        } catch (RuntimeException exception) {
            logFailure("password_grant_cleanup_failed", userId, exception);
        }
    }

    private static AuthException invalidGrant() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "INVALID_PASSWORD_TOKEN",
                "The password token is invalid or has expired.", "توکن تغییر رمز نامعتبر یا منقضی شده است.");
    }

    private static AuthException staleOrClaimed() {
        return new AuthException(HttpStatus.CONFLICT, "PASSWORD_UPDATE_CONFLICT",
                "A password update is already in progress or the credentials have changed.",
                "تغییر رمز در حال انجام است یا اطلاعات ورود تغییر کرده است.");
    }

    private static void logFailure(String event, Long userId, RuntimeException exception) {
        log.atWarn().addKeyValue("event", event).addKeyValue("user_id", userId)
                .addKeyValue("reason", exception instanceof UserClientException remote ? remote.getCode() : exception.getClass().getSimpleName())
                .log("Password workflow dependency could not complete.");
    }

    private record SessionIdentity(UUID id, long userId, long version) {}
    private record PasswordUpdate(PasswordGrant grant, long version) {}
}
