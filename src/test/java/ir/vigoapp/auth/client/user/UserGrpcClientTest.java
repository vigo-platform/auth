package ir.vigoapp.auth.client.user;

import io.grpc.*;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import ir.vigoapp.auth.config.ApplicationProperties;
import ir.vigoapp.auth.config.UserGrpcConfig;
import ir.vigoapp.auth.client.user.model.ChangePasswordCommand;
import ir.vigoapp.auth.client.user.model.CreateUserCommand;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.client.user.model.UserLoginInfo;
import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.contracts.user.v1.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import static org.assertj.core.api.Assertions.*;

class UserGrpcClientTest {
    private Server server;
    private ApplicationProperties properties;
    private ManagedChannel channel;
    private UserGrpcClient client;
    private final FakeUser user = new FakeUser();

    @BeforeEach
    void start() throws Exception {
        server = NettyServerBuilder.forAddress(new InetSocketAddress("127.0.0.1", 0)).addService(user).build().start();
        properties = new ApplicationProperties();
        properties.getUserGrpc().setHost("127.0.0.1");
        properties.getUserGrpc().setPort(server.getPort());
        var config = new UserGrpcConfig(properties);
        channel = config.userGrpcChannel();
        client = new UserGrpcClient(config.userServiceStub(channel), properties);
    }

    @AfterEach
    void stop() throws Exception {
        if (channel != null) channel.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
        if (server != null) server.shutdownNow().awaitTermination(5, TimeUnit.SECONDS);
    }

    @Test
    void allEightMethodsTransferFieldsAndReturnDomainModels() {
        var login = client.getLoginInfoByEmail("user@example.com");
        assertThat(login.passwordHash()).isEqualTo("encoded-hash");
        assertThat(login.user().credentialsExpired()).isTrue();
        assertThat(login.user().status()).isEqualTo(UserAccount.AccountStatus.ACTIVE);
        assertThat(login.user().roles()).containsExactly("USER");
        assertThat(login.user().phone()).isNull();
        assertThat(login.user().emailVerified()).isTrue();
        assertThat(login.user().credentialVersion()).isEqualTo(3);
        client.getLoginInfoByPhone("+989121234567");
        client.getLoginInfoById(7);
        assertThat(client.getUserById(7).userId()).isEqualTo(7);
        assertThat(client.checkEmailExists("user@example.com")).isTrue();
        assertThat(client.checkPhoneExists("+989121234567")).isFalse();
        assertThat(client.createUser(new CreateUserCommand("user@example.com", null, "A", "B", "hash"))
                .userId()).isEqualTo(7);
        assertThat(client.changeUserPassword(new ChangePasswordCommand(7, "next-hash", 3))).isEqualTo(4);
        assertThat(user.requests).hasSize(8);
        assertThat(((GetUserLoginInfoByEmailRequest) user.requests.get(0)).getEmail()).isEqualTo("user@example.com");
        assertThat(((GetUserLoginInfoByPhoneRequest) user.requests.get(1)).getPhone()).isEqualTo("+989121234567");
        assertThat(((GetUserLoginInfoByIdRequest) user.requests.get(2)).getUserId()).isEqualTo(7);
        assertThat(((GetUserByIdRequest) user.requests.get(3)).getUserId()).isEqualTo(7);
        assertThat(((CheckEmailExistsRequest) user.requests.get(4)).getEmail()).isEqualTo("user@example.com");
        assertThat(((CheckPhoneExistsRequest) user.requests.get(5)).getPhone()).isEqualTo("+989121234567");
        var create = (CreateUserRequest) user.requests.get(6);
        assertThat(create.getEmail()).isEqualTo("user@example.com");
        assertThat(create.hasPhone()).isFalse();
        assertThat(create.getFirstName()).isEqualTo("A");
        assertThat(create.getLastName()).isEqualTo("B");
        assertThat(create.getPasswordHash()).isEqualTo("hash");
        var change = (ChangeUserPasswordRequest) user.requests.get(7);
        assertThat(change.getUserId()).isEqualTo(7);
        assertThat(change.getExpectedCredentialVersion()).isEqualTo(3);
        assertThat(change.getNewPasswordHash()).isEqualTo("next-hash");
    }

    @Test
    void preservesOptionalIdentifiersAndRedactsCredentials() {
        var command = new CreateUserCommand(null, "+989121234567", null, null, "original-salted-hash");
        client.createUser(command);
        var create = (CreateUserRequest) user.requests.get(0);
        assertThat(create.hasEmail()).isFalse();
        assertThat(create.getPhone()).isEqualTo("+989121234567");
        assertThat(create.getPasswordHash()).isEqualTo("original-salted-hash");
        assertThat(command.toString()).doesNotContain("original-salted-hash");
        assertThat(new ChangePasswordCommand(7, "secret", 3).toString()).doesNotContain("secret");
        assertThat(client.getLoginInfoById(7).toString()).doesNotContain("encoded-hash");
    }

    @ParameterizedTest
    @CsvSource({"NOT_FOUND,NOT_FOUND", "ALREADY_EXISTS,ALREADY_EXISTS", "INVALID_ARGUMENT,INVALID_ARGUMENT",
            "ABORTED,CONFLICT", "UNAVAILABLE,UNAVAILABLE", "DEADLINE_EXCEEDED,TIMEOUT",
            "PERMISSION_DENIED,PERMISSION_DENIED", "UNAUTHENTICATED,UNAUTHENTICATED",
            "CANCELLED,CANCELLED", "RESOURCE_EXHAUSTED,RESOURCE_EXHAUSTED",
            "FAILED_PRECONDITION,FAILED_PRECONDITION", "UNKNOWN,INTERNAL"})
    void mapsErrorsWithoutLeakingRemoteDescriptions(Status.Code remote, UserClientException.Code expected) {
        user.failure = Status.fromCode(remote).withDescription("secret password hash");
        assertThatThrownBy(() -> client.getUserById(7)).isInstanceOfSatisfying(UserClientException.class, e -> {
            assertThat(e.getCode()).isEqualTo(expected);
            assertThat(e.getMessage()).doesNotContain("secret");
            assertThat(e.getCause()).isNull();
        });
    }

    @Test
    void doesNotRetryFailedMutations() {
        user.failure = Status.UNAVAILABLE;
        assertThatThrownBy(() -> client.createUser(new CreateUserCommand("user@example.com", null, null, null, "hash")))
                .isInstanceOf(UserClientException.class);
        assertThat(user.requests).hasSize(1);
        assertThatThrownBy(() -> client.changeUserPassword(new ChangePasswordCommand(7, "hash", 3)))
                .isInstanceOf(UserClientException.class);
        assertThat(user.requests).hasSize(2);
    }

    @Test
    void deadlineBoundsCallAndIsRenewedForTheNextCall() {
        client.getUserById(7); // Establish transport before exercising a short deadline.
        properties.getUserGrpc().setTimeoutMs(150);
        client = new UserGrpcClient(UserServiceGrpc.newBlockingStub(channel), properties);
        user.neverRespond = true;
        assertThatThrownBy(() -> client.getUserById(7)).isInstanceOfSatisfying(UserClientException.class,
                e -> assertThat(e.getCode()).isEqualTo(UserClientException.Code.TIMEOUT));
        user.neverRespond = false;
        assertThat(client.getUserById(7).userId()).isEqualTo(7);
        assertThat(user.deadlines).allMatch(value -> value > 0);
    }

    @Test
    void invalidCommandsDoNotReachTheServer() {
        assertThatThrownBy(() -> client.getUserById(0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client.getLoginInfoByEmail(" ")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client.checkPhoneExists("09121234567")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client.createUser(new CreateUserCommand(null, null, null, null, "hash")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client.createUser(new CreateUserCommand("user@example.com", null, null, null, "")))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client.changeUserPassword(new ChangePasswordCommand(7, "", 3)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client.changeUserPassword(new ChangePasswordCommand(7, "hash", 0)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(user.requests).isEmpty();
    }

    @Test
    void rejectsIncompleteResponsesAndPreservesUnknownAccountStatus() {
        user.login = UserLoginInfoResponse.getDefaultInstance();
        assertThatThrownBy(() -> client.getLoginInfoById(7)).isInstanceOfSatisfying(UserClientException.class,
                e -> assertThat(e.getCode()).isEqualTo(UserClientException.Code.INVALID_RESPONSE));
        user.account = user.account.toBuilder().setStatusValue(999).build();
        assertThat(client.getUserById(7).status()).isEqualTo(UserAccount.AccountStatus.UNKNOWN);
        user.account = UserAuthInfo.getDefaultInstance();
        assertThatThrownBy(() -> client.getUserById(7)).isInstanceOf(UserClientException.class);
    }

    private static class FakeUser extends UserServiceGrpc.UserServiceImplBase {
        final List<Object> requests = new CopyOnWriteArrayList<>();
        final List<Long> deadlines = new CopyOnWriteArrayList<>();
        volatile Status failure;
        volatile boolean neverRespond;
        volatile UserAuthInfo account = UserAuthInfo.newBuilder().setUserId(7).setCredentialVersion(3)
                .setEmail("user@example.com").setEmailVerified(true).addRoles("USER")
                .setStatus(UserStatus.USER_STATUS_ACTIVE).setCredentialsExpired(true).build();
        volatile UserLoginInfoResponse login = UserLoginInfoResponse.newBuilder().setUser(account)
                .setPasswordHash("encoded-hash").build();

        private <T> void respond(Object request, T response, StreamObserver<T> observer) {
            requests.add(request);
            deadlines.add(Context.current().getDeadline().timeRemaining(TimeUnit.NANOSECONDS));
            if (neverRespond) return;
            if (failure != null) { observer.onError(failure.asRuntimeException()); return; }
            observer.onNext(response);
            observer.onCompleted();
        }
        @Override public void getUserLoginInfoByEmail(GetUserLoginInfoByEmailRequest r, StreamObserver<UserLoginInfoResponse> o) { respond(r, login, o); }
        @Override public void getUserLoginInfoByPhone(GetUserLoginInfoByPhoneRequest r, StreamObserver<UserLoginInfoResponse> o) { respond(r, login, o); }
        @Override public void getUserLoginInfoById(GetUserLoginInfoByIdRequest r, StreamObserver<UserLoginInfoResponse> o) { respond(r, login, o); }
        @Override public void getUserById(GetUserByIdRequest r, StreamObserver<UserAuthInfo> o) { respond(r, account, o); }
        @Override public void checkEmailExists(CheckEmailExistsRequest r, StreamObserver<ExistsResponse> o) { respond(r, ExistsResponse.newBuilder().setExists(true).build(), o); }
        @Override public void checkPhoneExists(CheckPhoneExistsRequest r, StreamObserver<ExistsResponse> o) { respond(r, ExistsResponse.getDefaultInstance(), o); }
        @Override public void createUser(CreateUserRequest r, StreamObserver<CreateUserResponse> o) { respond(r, CreateUserResponse.newBuilder().setUser(account).build(), o); }
        @Override public void changeUserPassword(ChangeUserPasswordRequest r, StreamObserver<ChangeUserPasswordResponse> o) { respond(r, ChangeUserPasswordResponse.newBuilder().setCredentialVersion(4).build(), o); }
    }
}
