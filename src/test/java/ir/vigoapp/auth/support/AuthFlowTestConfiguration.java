package ir.vigoapp.auth.support;

import ir.vigoapp.auth.client.user.UserGrpcClient;
import ir.vigoapp.auth.config.AuthProperties;
import ir.vigoapp.auth.security.SecureTokens;
import ir.vigoapp.auth.service.AuthSettingService;
import ir.vigoapp.auth.service.AuthProtectionService;
import ir.vigoapp.auth.service.NotificationService;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Clock;

import static org.mockito.Mockito.*;

/** External boundaries are replaced; rate limits and challenge transitions still use real Redis. */
@TestConfiguration(proxyBeanMethods = false)
public class AuthFlowTestConfiguration {
    @Bean @Primary UserGrpcClient testUsers() { return classMock(UserGrpcClient.class); }
    @Bean @Primary AuthSettingService testSettings() { return classMock(AuthSettingService.class); }
    @Bean @Primary NotificationService testNotifications() { return classMock(NotificationService.class); }
    @Bean @Primary Clock testClock() { return classMock(Clock.class); }
    @Bean @Primary @Qualifier("loginOtpDeliveryExecutor")
    TaskExecutor testLoginOtpDeliveryExecutor() { return new SyncTaskExecutor(); }

    @Bean @Primary
    AuthProtectionService testProtection(StringRedisTemplate redis, AuthProperties properties, SecureTokens tokens) {
        return mock(AuthProtectionService.class, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS)
                .spiedInstance(new AuthProtectionService(redis, properties, tokens)).defaultAnswer(CALLS_REAL_METHODS));
    }

    // The project's default Mockito maker supports interfaces only; select subclass mocks for these classes.
    private static <T> T classMock(Class<T> type) {
        return mock(type, withSettings().mockMaker(org.mockito.MockMakers.SUBCLASS));
    }
}
