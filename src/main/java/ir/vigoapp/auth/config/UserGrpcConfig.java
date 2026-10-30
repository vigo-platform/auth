package ir.vigoapp.auth.config;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import ir.vigoapp.contracts.user.v1.UserServiceGrpc;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class UserGrpcConfig {
    private final ApplicationProperties applicationProperties;

    @Bean(destroyMethod = "shutdownNow")
    public ManagedChannel userGrpcChannel() {
        var properties = applicationProperties.getUserGrpc();
        return ManagedChannelBuilder.forAddress(properties.getHost(), properties.getPort())
                .usePlaintext()
                .disableRetry()
                .disableServiceConfigLookUp()
                .build();
    }

    @Bean
    public UserServiceGrpc.UserServiceBlockingStub userServiceStub(
            @Qualifier("userGrpcChannel") ManagedChannel channel) {
        return UserServiceGrpc.newBlockingStub(channel);
    }
}
