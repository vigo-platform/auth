package ir.vigoapp.auth.client.user;

import io.grpc.StatusRuntimeException;
import ir.vigoapp.auth.config.ApplicationProperties;
import ir.vigoapp.auth.client.user.model.ChangePasswordCommand;
import ir.vigoapp.auth.client.user.model.CreateUserCommand;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.client.user.model.UserLoginInfo;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.contracts.user.v1.*;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.concurrent.TimeUnit;
import java.util.function.Function;

/** Client for the User service gRPC API. */
@Component
public class UserGrpcClient {
    private final UserServiceGrpc.UserServiceBlockingStub stub;
    private final long timeoutMs;

    public UserGrpcClient(UserServiceGrpc.UserServiceBlockingStub stub, ApplicationProperties properties) {
        this.stub = stub;
        this.timeoutMs = properties.getUserGrpc().getTimeoutMs();
    }

    public UserLoginInfo getLoginInfoByEmail(String email) {
        Assert.hasText(email, "email is required");
        String operation = "GetUserLoginInfoByEmail";
        var response = call(operation, s -> s.getUserLoginInfoByEmail(
                GetUserLoginInfoByEmailRequest.newBuilder().setEmail(email).build()));
        return loginInfo(response, operation);
    }

    public UserLoginInfo getLoginInfoByPhone(String phone) {
        validatePhone(phone);
        String operation = "GetUserLoginInfoByPhone";
        var response = call(operation, s -> s.getUserLoginInfoByPhone(
                GetUserLoginInfoByPhoneRequest.newBuilder().setPhone(phone).build()));
        return loginInfo(response, operation);
    }

    public UserLoginInfo getLoginInfoById(long userId) {
        Assert.isTrue(userId > 0, "userId must be positive");
        String operation = "GetUserLoginInfoById";
        var response = call(operation, s -> s.getUserLoginInfoById(
                GetUserLoginInfoByIdRequest.newBuilder().setUserId(userId).build()));
        return loginInfo(response, operation);
    }

    public UserAccount getUserById(long userId) {
        Assert.isTrue(userId > 0, "userId must be positive");
        String operation = "GetUserById";
        return account(call(operation, s -> s.getUserById(
                GetUserByIdRequest.newBuilder().setUserId(userId).build())), operation);
    }

    public boolean checkEmailExists(String email) {
        Assert.hasText(email, "email is required");
        return call("CheckEmailExists", s -> s.checkEmailExists(
                CheckEmailExistsRequest.newBuilder().setEmail(email).build())).getExists();
    }

    public boolean checkPhoneExists(String phone) {
        validatePhone(phone);
        return call("CheckPhoneExists", s -> s.checkPhoneExists(
                CheckPhoneExistsRequest.newBuilder().setPhone(phone).build())).getExists();
    }

    public UserAccount createUser(CreateUserCommand command) {
        Assert.notNull(command, "command is required");
        Assert.isTrue(command.email() != null || command.phone() != null, "email or phone is required");
        Assert.hasText(command.passwordHash(), "passwordHash is required");
        var request = CreateUserRequest.newBuilder()
                .setPasswordHash(command.passwordHash());
        if (command.email() != null) {
            Assert.hasText(command.email(), "email must not be blank when supplied");
            request.setEmail(command.email());
        }
        if (command.phone() != null) {
            validatePhone(command.phone());
            request.setPhone(command.phone());
        }
        if (command.firstName() != null) request.setFirstName(command.firstName());
        if (command.lastName() != null) request.setLastName(command.lastName());
        String operation = "CreateUser";
        var response = call(operation, s -> s.createUser(request.build()));
        requireResponse(response.hasUser(), operation);
        return account(response.getUser(), operation);
    }

    public long changeUserPassword(ChangePasswordCommand command) {
        Assert.notNull(command, "command is required");
        Assert.isTrue(command.userId() > 0, "userId must be positive");
        Assert.isTrue(command.expectedCredentialVersion() > 0, "expectedCredentialVersion must be positive");
        Assert.hasText(command.newPasswordHash(), "newPasswordHash is required");
        var request = ChangeUserPasswordRequest.newBuilder()
                .setUserId(command.userId())
                .setNewPasswordHash(command.newPasswordHash())
                .setExpectedCredentialVersion(command.expectedCredentialVersion()).build();
        String operation = "ChangeUserPassword";
        var response = call(operation, s -> s.changeUserPassword(request));
        requireResponse(response.getCredentialVersion() > command.expectedCredentialVersion(), operation);
        return response.getCredentialVersion();
    }

    private <T> T call(String operation, Function<UserServiceGrpc.UserServiceBlockingStub, T> rpc) {
        try {
            // A fresh relative deadline per call; the shared stub must never hold an aging deadline.
            return rpc.apply(stub.withDeadlineAfter(timeoutMs, TimeUnit.MILLISECONDS));
        } catch (StatusRuntimeException exception) {
            var code = switch (exception.getStatus().getCode()) {
                case INVALID_ARGUMENT -> UserClientException.Code.INVALID_ARGUMENT;
                case NOT_FOUND -> UserClientException.Code.NOT_FOUND;
                case ALREADY_EXISTS -> UserClientException.Code.ALREADY_EXISTS;
                case ABORTED -> UserClientException.Code.CONFLICT;
                case UNAUTHENTICATED -> UserClientException.Code.UNAUTHENTICATED;
                case PERMISSION_DENIED -> UserClientException.Code.PERMISSION_DENIED;
                case UNAVAILABLE -> UserClientException.Code.UNAVAILABLE;
                case DEADLINE_EXCEEDED -> UserClientException.Code.TIMEOUT;
                case CANCELLED -> UserClientException.Code.CANCELLED;
                case RESOURCE_EXHAUSTED -> UserClientException.Code.RESOURCE_EXHAUSTED;
                case FAILED_PRECONDITION -> UserClientException.Code.FAILED_PRECONDITION;
                default -> UserClientException.Code.INTERNAL;
            };
            // Remote descriptions/trailers may contain credentials. Do not attach them as a cause.
            throw new UserClientException(code, operation);
        }
    }

    private static UserLoginInfo loginInfo(UserLoginInfoResponse response, String operation) {
        requireResponse(response.hasUser() && !response.getPasswordHash().isBlank(), operation);
        return new UserLoginInfo(account(response.getUser(), operation), response.getPasswordHash());
    }

    private static UserAccount account(UserAuthInfo response, String operation) {
        requireResponse(response.getUserId() > 0 && response.getCredentialVersion() > 0, operation);
        var status = switch (response.getStatus()) {
            case USER_STATUS_PENDING_VERIFICATION -> UserAccount.AccountStatus.PENDING_VERIFICATION;
            case USER_STATUS_ACTIVE -> UserAccount.AccountStatus.ACTIVE;
            case USER_STATUS_SUSPENDED -> UserAccount.AccountStatus.SUSPENDED;
            case USER_STATUS_DEACTIVATED -> UserAccount.AccountStatus.DEACTIVATED;
            default -> UserAccount.AccountStatus.UNKNOWN;
        };
        return new UserAccount(response.getUserId(), response.getRolesList(),
                response.hasEmail() ? response.getEmail() : null,
                response.hasPhone() ? response.getPhone() : null, status,
                response.getEmailVerified(), response.getPhoneVerified(),
                response.getCredentialVersion(), response.getCredentialsExpired());
    }

    private static void requireResponse(boolean valid, String operation) {
        if (!valid) throw new UserClientException(UserClientException.Code.INVALID_RESPONSE, operation);
    }

    private static void validatePhone(String phone) {
        Assert.isTrue(phone != null && phone.matches("\\+[1-9][0-9]{1,14}"), "phone must be in E.164 format");
    }
}
