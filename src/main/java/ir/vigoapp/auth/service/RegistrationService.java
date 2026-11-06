package ir.vigoapp.auth.service;

import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.CreateUserCommand;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.registration.RegistrationInitiateRequest;
import ir.vigoapp.auth.dto.registration.RegistrationInitiateResponse;
import ir.vigoapp.auth.dto.registration.RegistrationVerifyRequest;
import ir.vigoapp.auth.dto.registration.RegistrationVerifyResponse;
import ir.vigoapp.auth.dto.registration.RegisterRequest;
import ir.vigoapp.auth.dto.registration.RegisterResponse;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.model.registration.RegistrationChallenge;
import ir.vigoapp.auth.model.registration.RegistrationGrant;
import ir.vigoapp.auth.repository.registration.RegistrationRepository;
import ir.vigoapp.auth.security.PasswordPolicy;
import ir.vigoapp.auth.security.SecureTokens;
import ir.vigoapp.auth.security.login.AccountEligibility;
import ir.vigoapp.auth.security.login.LoginIdentifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Clock;

@Service
@RequiredArgsConstructor
@Slf4j
public class RegistrationService {
    private final AuthPolicyService policy;
    private final AuthProtectionService protection;
    private final UserGrpcClient users;
    private final SessionService sessions;
    private final PasswordEncoder passwords;
    private final RegistrationRepository registrations;
    private final NotificationService notifications;
    private final SecureTokens tokens;
    private final AuthProperties properties;
    private final Clock clock;

    public RegistrationInitiateResponse initiate(RegistrationInitiateRequest request, ClientInfo client) {
        policy.requireRegistrationEnabled();
        String identifier = LoginIdentifier.normalize(request.identifier());
        OtpChannel channel = identifier.contains("@") ? OtpChannel.EMAIL : OtpChannel.SMS;
        policy.requireRegistrationOtpEnabled(channel);
        protection.checkIp(client);
        String identifierKey = protection.identifierKey(identifier);
        protection.requireUnlocked(identifierKey);
        protection.reserveIdentifierCooldown(identifierKey);
        boolean exists = channel == OtpChannel.EMAIL ? users.checkEmailExists(identifier) : users.checkPhoneExists(identifier);
        if (exists) throw alreadyExists();

        // Settings may change while the existence check is in flight.
        policy.requireRegistrationOtpEnabled(channel);
        String token = tokens.randomToken();
        String code = tokens.otp();
        var challenge = RegistrationChallenge.builder().token(token).identifier(identifier).channel(channel)
                .expiresAt(clock.instant().plus(properties.getOtpTtl())).failedAttempts(0).build();
        registrations.create(challenge, code);
        try {
            policy.requireRegistrationOtpEnabled(channel);
            notifications.sendRegistrationOtp(channel, identifier, code, challenge.expiresAt(), OtpNotificationContext.current());
        } catch (RuntimeException exception) {
            // Delete only our challenge; a newer request must not be invalidated by a slow failure.
            try {
                registrations.deleteChallenge(token);
            } catch (RuntimeException cleanupFailure) {
                log.atWarn().addKeyValue("event", "registration_challenge_cleanup_failed")
                        .addKeyValue("reason", cleanupFailure.getClass().getSimpleName())
                        .addKeyValue("ip_address", client.ipAddress()).log("Failed registration delivery could not be cleaned up.");
            }
            throw exception;
        }
        log.atInfo().addKeyValue("event", "registration_challenge_created").addKeyValue("result", "SUCCESS")
                .addKeyValue("subject", protection.auditSubject(identifierKey)).addKeyValue("channel", channel)
                .addKeyValue("expires_in_seconds", properties.getOtpTtl().toSeconds())
                .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                .addKeyValue("device_id", client.deviceId()).log("Registration verification code requested.");
        return RegistrationInitiateResponse.builder().mfaToken(token).channel(channel)
                .expiresIn(properties.getOtpTtl().toSeconds()).resendAfter(properties.getOtpCooldown().toSeconds()).build();
    }

    public RegistrationVerifyResponse verify(RegistrationVerifyRequest request, ClientInfo client) {
        policy.requireRegistrationEnabled();
        protection.checkIp(client);
        var challenge = registrations.findChallenge(request.mfaToken()).orElseThrow(AuthException::invalidOtp);
        policy.requireRegistrationOtpEnabled(challenge.channel());
        String identifierKey = protection.identifierKey(challenge.identifier());
        protection.requireUnlocked(identifierKey);
        String registrationToken = tokens.randomToken();
        policy.requireRegistrationOtpEnabled(challenge.channel());
        int result = registrations.verify(request.mfaToken(), request.otp(), registrationToken, clock.instant());
        if (result != 1) {
            if (result < 0) protection.failed(identifierKey, null);
            log.atWarn().addKeyValue("event", "registration_otp_rejected").addKeyValue("result", "FAILURE")
                    .addKeyValue("subject", protection.auditSubject(identifierKey)).addKeyValue("channel", challenge.channel())
                    .addKeyValue("reason", result < 0 ? "incorrect_code" : "challenge_unavailable")
                    .addKeyValue("attempts", result < 0 ? -result : null)
                    .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                    .addKeyValue("device_id", client.deviceId()).log("Registration verification rejected.");
            throw AuthException.invalidOtp();
        }
        log.atInfo().addKeyValue("event", "registration_otp_verified").addKeyValue("result", "SUCCESS")
                .addKeyValue("subject", protection.auditSubject(identifierKey)).addKeyValue("channel", challenge.channel())
                .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                .addKeyValue("device_id", client.deviceId()).log("Registration contact verified.");
        return RegistrationVerifyResponse.builder().registrationToken(registrationToken)
                .expiresIn(properties.getRegistrationTokenTtl().toSeconds()).build();
    }

    public RegisterResponse complete(RegisterRequest request, ClientInfo client) {
        policy.requireRegistrationEnabled();
        protection.checkIp(client);
        PasswordPolicy.validateNewPassword(request.password());
        var grant = registrations.findGrant(request.registrationToken()).orElseThrow(this::invalidRegistrationToken);
        policy.requireRegistrationOtpEnabled(grant.channel());
        if (!grant.expiresAt().isAfter(clock.instant())) throw invalidRegistrationToken();
        if (!grant.isOpen()) {
            if (grant.isClaimed()) throw registrationInProgress();
            // Completed result hashes left by the previous implementation are no longer usable.
            throw invalidRegistrationToken();
        }
        String identifierKey = protection.identifierKey(grant.identifier());
        protection.requireUnlocked(identifierKey);
        // The only contact comes from the verified Redis proof, never from the completion body.
        var command = CreateUserCommand.builder()
                .email(grant.channel() == OtpChannel.EMAIL ? grant.identifier() : null)
                .phone(grant.channel() == OtpChannel.SMS ? grant.identifier() : null)
                .firstName(request.firstName()).lastName(request.lastName())
                .passwordHash(passwords.encode(request.password())).build();
        policy.requireRegistrationOtpEnabled(grant.channel());
        protection.requireUnlocked(identifierKey);
        String owner = tokens.randomToken();
        if (!registrations.claim(request.registrationToken(), owner, clock.instant())) {
            // A competing completion may already have consumed the proof while we were hashing.
            var latest = registrations.findGrant(request.registrationToken()).orElseThrow(this::invalidRegistrationToken);
            if (!latest.expiresAt().isAfter(clock.instant()) || !latest.isClaimed()) throw invalidRegistrationToken();
            throw registrationInProgress();
        }
        try {
            policy.requireRegistrationOtpEnabled(grant.channel());
        } catch (AuthException exception) {
            // Nothing was sent to User yet, so this claim can safely be retried after re-enabling settings.
            registrations.release(request.registrationToken(), owner);
            throw exception;
        }

        UserAccount user;
        try {
            user = users.createUser(command);
            String returnedContact = grant.channel() == OtpChannel.EMAIL ? user.email() : user.phone();
            if (!LoginIdentifier.matches(grant.identifier(), returnedContact)) {
                throw new UserClientException(UserClientException.Code.INVALID_RESPONSE, "CreateUser");
            }
        } catch (UserClientException exception) {
            log.atWarn().addKeyValue("event", "registration_creation_failed").addKeyValue("result", "FAILURE")
                    .addKeyValue("reason", exception.getCode()).addKeyValue("operation", exception.getOperation())
                    .addKeyValue("subject", protection.auditSubject(identifierKey)).addKeyValue("channel", grant.channel())
                    .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                    .addKeyValue("device_id", client.deviceId()).log("Account creation through the User service failed.");
            // INVALID_ARGUMENT is a definitive rejection before creation; correcting the form may retry.
            // All ambiguous mutation failures stay claimed: CreateUser has no idempotency key.
            if (exception.getCode() == UserClientException.Code.INVALID_ARGUMENT) {
                registrations.release(request.registrationToken(), owner);
                throw invalidRequest();
            }
            if (exception.getCode() == UserClientException.Code.ALREADY_EXISTS) throw alreadyExists();
            throw exception;
        }
        // The User mutation is committed even if the Auth session cannot be created.
        consumeGrant(grant, owner, user, client);
        log.atInfo().addKeyValue("event", "registration_success").addKeyValue("result", "SUCCESS")
                .addKeyValue("user_id", user.userId()).addKeyValue("account_status", user.status())
                .addKeyValue("channel", grant.channel()).addKeyValue("ip_address", client.ipAddress())
                .addKeyValue("user_agent", client.userAgent()).addKeyValue("device_id", client.deviceId())
                .log("User account created from a verified registration contact.");
        var issuedTokens = AccountEligibility.canLogin(user) && policy.isLoginEnabled()
                ? sessions.create(user, client) : null;
        return RegisterResponse.builder().userId(user.userId()).status(user.status()).tokens(issuedTokens).build();
    }

    private void consumeGrant(RegistrationGrant grant, String owner, UserAccount user, ClientInfo client) {
        try {
            // A missing/expired grant is already unusable; only the owner can delete an existing claim.
            registrations.complete(grant.token(), owner);
        } catch (RuntimeException exception) {
            // User already committed. A failed cleanup leaves the grant CLAIMED, so it cannot create again.
            log.atWarn().addKeyValue("event", "registration_grant_cleanup_failed").addKeyValue("user_id", user.userId())
                    .addKeyValue("reason", exception.getClass().getSimpleName()).addKeyValue("ip_address", client.ipAddress())
                    .log("Created account registration claim could not be removed.");
        }
        try {
            protection.clearFailures(protection.identifierKey(grant.identifier()), user.userId());
        } catch (RuntimeException exception) {
            log.atWarn().addKeyValue("event", "registration_counter_cleanup_failed").addKeyValue("user_id", user.userId())
                    .addKeyValue("reason", exception.getClass().getSimpleName()).addKeyValue("ip_address", client.ipAddress())
                    .log("Created account could not clear its failure counters.");
        }
    }

    private AuthException alreadyExists() {
        return new AuthException(HttpStatus.CONFLICT, "ACCOUNT_ALREADY_EXISTS",
                "An account with these details already exists. Please sign in.", "حسابی با این اطلاعات قبلاً ثبت شده است. وارد شوید.");
    }

    private AuthException invalidRegistrationToken() {
        return new AuthException(HttpStatus.UNAUTHORIZED, "INVALID_REGISTRATION_TOKEN",
                "Registration verification is invalid, expired, or already used. Please request a new code.",
                "تأیید ثبت‌نام نامعتبر، منقضی یا قبلاً استفاده شده است. کد جدید درخواست کنید.");
    }

    private AuthException registrationInProgress() {
        return new AuthException(HttpStatus.CONFLICT, "REGISTRATION_IN_PROGRESS",
                "Account creation is in progress or its outcome is uncertain. Try signing in or request a new verification code.",
                "ساخت حساب در حال انجام است یا نتیجه آن مشخص نیست. ورود را امتحان کنید یا کد تأیید جدید بگیرید.");
    }

    private AuthException invalidRequest() {
        return new AuthException(HttpStatus.BAD_REQUEST, "INVALID_REQUEST",
                "The registration details are invalid.", "اطلاعات ثبت‌نام معتبر نیست.");
    }
}
