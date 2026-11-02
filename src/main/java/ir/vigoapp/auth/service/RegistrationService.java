package ir.vigoapp.auth.service;

import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.client.user.model.CreateUserCommand;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.registration.RegisterRequest;
import ir.vigoapp.auth.dto.registration.RegisterResponse;
import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.security.login.LoginIdentifier;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Service
@RequiredArgsConstructor
@Slf4j
public class RegistrationService {
    private final AuthPolicyService policy;
    private final LoginProtectionService protection;
    private final UserGrpcClient users;
    private final PasswordEncoder passwords;

    public RegisterResponse register(RegisterRequest request, ClientInfo client) {
        policy.requireRegistrationEnabled();
        protection.checkIp(client);
        if (request.email() == null && request.phone() == null) throw invalidRequest();
        String email = request.email() == null ? null : LoginIdentifier.normalize(request.email());
        String phone = request.phone() == null ? null : LoginIdentifier.normalize(request.phone());
        if ((email != null && !email.contains("@")) || (phone != null && phone.contains("@"))) {
            throw invalidRequest();
        }
        if (request.password() == null || request.password().isBlank() || request.password().length() < 8) {
            throw invalidRequest();
        }
        if (request.password().getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new AuthException(HttpStatus.BAD_REQUEST, "INVALID_PASSWORD_LENGTH",
                    "Password must not exceed 72 UTF-8 bytes.", "طول رمز عبور نباید بیش از ۷۲ بایت باشد.");
        }
        var command = CreateUserCommand.builder().email(email).phone(phone)
                .firstName(request.firstName()).lastName(request.lastName())
                .passwordHash(passwords.encode(request.password())).build();
        // Recheck after bcrypt work, immediately before the remote account-creation side effect.
        policy.requireRegistrationEnabled();
        try {
            var user = users.createUser(command);
            if ((email != null && !LoginIdentifier.matches(email, user.email()))
                    || (phone != null && !LoginIdentifier.matches(phone, user.phone()))) {
                throw new UserClientException(UserClientException.Code.INVALID_RESPONSE, "CreateUser");
            }
            log.atInfo().addKeyValue("event", "registration_success").addKeyValue("user_id", user.userId())
                    .addKeyValue("account_status", user.status()).addKeyValue("ip_address", client.ipAddress())
                    .addKeyValue("user_agent", client.userAgent()).addKeyValue("device_id", client.deviceId())
                    .log("User account created.");
            return RegisterResponse.builder().userId(user.userId()).status(user.status()).build();
        } catch (UserClientException exception) {
            if (exception.getCode() == UserClientException.Code.ALREADY_EXISTS) {
                throw new AuthException(HttpStatus.CONFLICT, "ACCOUNT_ALREADY_EXISTS",
                        "An account with these details already exists.", "حسابی با این اطلاعات قبلاً ثبت شده است.");
            }
            if (exception.getCode() == UserClientException.Code.INVALID_ARGUMENT) throw invalidRequest();
            throw exception;
        }
    }

    private AuthException invalidRequest() {
        return new AuthException(HttpStatus.BAD_REQUEST, "INVALID_REQUEST",
                "The registration details are invalid.", "اطلاعات ثبت‌نام معتبر نیست.");
    }
}
