package ir.vigoapp.auth.config;

import io.grpc.ManagedChannel;
import ir.vigoapp.auth.client.user.UserGrpcClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.TimeUnit;
import static org.assertj.core.api.Assertions.assertThat;

class UserGrpcConfigTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class))
            .withUserConfiguration(ApplicationProperties.class, UserGrpcConfig.class, UserGrpcClient.class)
            .withPropertyValues("app.user-grpc.host=localhost", "app.user-grpc.port=50051",
                    "app.auth-defaults.default-otp-channel=EMAIL");

    @Test
    void bindsApplicationPropertiesCreatesServiceAndClosesChannel() throws Exception {
        AtomicReference<ManagedChannel> channel = new AtomicReference<>();
        runner.withPropertyValues("app.user-grpc.timeout-ms=4321", "app.public-paths[0]=/public")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(UserGrpcClient.class);
                    var application = context.getBean(ApplicationProperties.class);
                    assertThat(application.getPublicPaths()).containsExactly("/public");
                    var properties = application.getUserGrpc();
                    assertThat(properties.getHost()).isEqualTo("localhost");
                    assertThat(properties.getPort()).isEqualTo(50051);
                    assertThat(properties.getTimeoutMs()).isEqualTo(4321);
                    channel.set(context.getBean(ManagedChannel.class));
                });
        assertThat(channel.get().awaitTermination(5, TimeUnit.SECONDS)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"app.user-grpc.host=", "app.user-grpc.host=https://localhost",
            "app.user-grpc.port=0", "app.user-grpc.port=65536", "app.user-grpc.timeout-ms=0",
            "app.user-grpc.typo=true"})
    void rejectsInvalidConfiguration(String setting) {
        runner.withPropertyValues(setting).run(context -> assertThat(context).hasFailed());
    }
}
