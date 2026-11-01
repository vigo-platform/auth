package ir.vigoapp.auth.service;

import ir.vigoapp.auth.bootstrap.AuthSettingInitializer;
import ir.vigoapp.auth.config.ApplicationProperties;
import ir.vigoapp.auth.entity.AuthSetting;
import ir.vigoapp.auth.entity.OtpChannel;
import ir.vigoapp.auth.repository.AuthSettingRepository;
import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.TransactionSystemException;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionTemplate;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Optional;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AuthSettingServiceTest {
    private final AuthSettingRepository repository = interfaceMock(AuthSettingRepository.class);
    private final Connection connection = interfaceMock(Connection.class);
    private final ApplicationProperties properties = new ApplicationProperties();
    private DataSourceTransactionManager transactionManager;
    private AuthSettingService service;
    private final Logger logger = (Logger) LoggerFactory.getLogger(AuthSettingService.class);
    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    private Level previousLevel;
    private boolean previousAdditive;

    @BeforeEach
    void setUp() throws SQLException {
        previousLevel = logger.getLevel();
        previousAdditive = logger.isAdditive();
        logger.setLevel(Level.INFO);
        logger.setAdditive(false);
        logs.setContext(logger.getLoggerContext());
        logs.start();
        logger.addAppender(logs);
        var dataSource = interfaceMock(DataSource.class);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.getAutoCommit()).thenReturn(true);
        transactionManager = new DataSourceTransactionManager(dataSource);

        var interceptor = new TransactionInterceptor();
        interceptor.setTransactionManager(transactionManager);
        interceptor.setTransactionAttributeSource(new AnnotationTransactionAttributeSource());
        var proxy = new ProxyFactory(new AuthSettingService(repository, properties));
        proxy.addAdvice(interceptor);
        service = (AuthSettingService) proxy.getProxy();
        properties.getAuthDefaults().setDefaultOtpChannel(OtpChannel.IN_APP);
        when(repository.saveAndFlush(any(AuthSetting.class))).thenAnswer(invocation -> {
            AuthSetting revision = invocation.getArgument(0);
            ReflectionTestUtils.setField(revision, "id", 2L);
            ReflectionTestUtils.setField(revision, "updatedAt", Instant.parse("2026-11-01T13:00:00Z"));
            return revision;
        });
    }

    @AfterEach
    void restoreLogging() {
        logger.detachAppender(logs);
        logs.stop();
        logger.setLevel(previousLevel);
        logger.setAdditive(previousAdditive);
    }

    @Test
    void startupCreatesMissingSettingsAndPublishesOnlyAfterCommit() throws Exception {
        var defaults = properties.getAuthDefaults();
        defaults.setLoginEnabled(true);
        defaults.setRegisterEnabled(false);
        defaults.setEmailNotificationEnabled(true);
        defaults.setSmsNotificationEnabled(false);
        defaults.setInAppNotificationEnabled(true);
        when(repository.findFirstByOrderByVersionDescIdDesc()).thenReturn(Optional.empty());
        when(repository.saveAndFlush(any(AuthSetting.class))).thenAnswer(invocation -> {
            AuthSetting setting = invocation.getArgument(0);
            assertThat(setting.isLoginEnabled()).isTrue();
            assertThat(setting.isRegisterEnabled()).isFalse();
            assertThat(setting.getDefaultOtpChannel()).isEqualTo(OtpChannel.IN_APP);
            assertThat(setting.isEmailNotificationEnabled()).isTrue();
            assertThat(setting.isSmsNotificationEnabled()).isFalse();
            assertThat(setting.isInAppNotificationEnabled()).isTrue();
            assertThat(setting.getId()).isNull();
            assertThat(setting.getVersion()).isEqualTo(1);
            ReflectionTestUtils.setField(setting, "id", 1L);
            ReflectionTestUtils.setField(setting, "updatedAt", Instant.parse("2026-11-01T12:00:00Z"));
            return setting;
        });
        doAnswer(invocation -> {
            assertThatThrownBy(service::getCurrent).isInstanceOf(IllegalStateException.class);
            assertThat(events("Auth settings created from defaults:")).isEmpty();
            return null;
        }).when(connection).commit();

        new AuthSettingInitializer(service).run(new DefaultApplicationArguments());

        assertThat(service.getCurrent().id()).isEqualTo(1);
        assertThat(service.getCurrent().updatedAt()).isEqualTo(Instant.parse("2026-11-01T12:00:00Z"));
        assertThat(events("Auth settings created from defaults:")).hasSize(1);
        assertThat(events("Auth settings created from defaults:").getFirst().getFormattedMessage()).contains("version=1");
        var order = inOrder(repository);
        order.verify(repository).lockForRevisionChange();
        order.verify(repository).findFirstByOrderByVersionDescIdDesc();
        order.verify(repository).saveAndFlush(any(AuthSetting.class));
    }

    @Test
    void startupPreservesExistingSettingsAndReadsUseOnlyTheCache() {
        var existing = setting(4);
        existing.setLoginEnabled(false);
        properties.getAuthDefaults().setLoginEnabled(true);
        when(repository.findFirstByOrderByVersionDescIdDesc()).thenReturn(Optional.of(existing));

        var snapshot = service.initialize();
        assertThat(snapshot.loginEnabled()).isFalse();
        assertThat(events("Auth settings loaded:")).hasSize(1);
        assertThat(events("Auth settings loaded:").getFirst().getFormattedMessage()).contains("version=4");
        verify(repository, never()).saveAndFlush(any());
        clearInvocations(repository);
        assertThat(service.getCurrent()).isSameAs(snapshot);
        assertThat(service.getCurrent()).isSameAs(snapshot);
        verifyNoInteractions(repository);
    }

    @Test
    void updateInsertsANewRevisionWithoutChangingHistoryAndPublishesOnlyAfterCommit() throws Exception {
        var existing = initializeExisting();
        doAnswer(invocation -> {
            assertThat(service.getCurrent().version()).isZero();
            assertThat(service.getCurrent().loginEnabled()).isTrue();
            assertThat(events("Auth settings updated:")).isEmpty();
            return null;
        }).when(connection).commit();

        var result = service.update(command(0));

        assertThat(service.getCurrent()).isSameAs(result);
        assertThat(result.version()).isEqualTo(1);
        assertThat(result.id()).isEqualTo(2);
        assertThat(existing.getId()).isEqualTo(1);
        assertThat(existing.getVersion()).isZero();
        assertThat(existing.isLoginEnabled()).isTrue();
        verify(repository).saveAndFlush(argThat(saved -> saved != existing && saved.getVersion() == 1));
        assertThat(result.updatedAt()).isEqualTo(Instant.parse("2026-11-01T13:00:00Z"));
        assertThat(result.loginEnabled()).isFalse();
        assertThat(result.registerEnabled()).isTrue();
        assertThat(result.defaultOtpChannel()).isEqualTo(OtpChannel.SMS);
        assertThat(result.emailNotificationEnabled()).isTrue();
        assertThat(result.smsNotificationEnabled()).isFalse();
        assertThat(result.inAppNotificationEnabled()).isTrue();
        assertThat(events("Auth settings updated:")).hasSize(1);
        assertThat(events("Auth settings updated:").getFirst().getFormattedMessage()).contains("version=1");
    }

    @Test
    void staleCallerVersionCannotOverwriteSettings() {
        initializeExisting();
        var previous = service.getCurrent();
        when(repository.findFirstByOrderByVersionDescIdDesc()).thenReturn(Optional.of(setting(1)));

        assertThatThrownBy(() -> service.update(command(0)))
                .isInstanceOf(ObjectOptimisticLockingFailureException.class);

        verify(repository, never()).saveAndFlush(any());
        assertThat(service.getCurrent()).isSameAs(previous);
    }

    @Test
    void eachChangeAppendsTheNextVersionAndPreservesPreviousSnapshots() {
        var latest = new java.util.concurrent.atomic.AtomicReference<AuthSetting>();
        when(repository.findFirstByOrderByVersionDescIdDesc())
                .thenAnswer(invocation -> Optional.ofNullable(latest.get()));
        when(repository.saveAndFlush(any(AuthSetting.class))).thenAnswer(invocation -> {
            AuthSetting revision = invocation.getArgument(0);
            assertThat(revision.getId()).isNull();
            ReflectionTestUtils.setField(revision, "id", revision.getVersion() + 10);
            ReflectionTestUtils.setField(revision, "updatedAt", Instant.parse("2026-11-01T12:00:00Z"));
            latest.set(revision);
            return revision;
        });

        var first = service.initialize();
        var second = service.update(first.toBuilder().loginEnabled(true).build());
        var third = service.update(second.toBuilder().registerEnabled(true).build());

        assertThat(first.version()).isEqualTo(1);
        assertThat(second.version()).isEqualTo(2);
        assertThat(third.version()).isEqualTo(3);
        assertThat(first.loginEnabled()).isFalse();
        assertThat(second.loginEnabled()).isTrue();
        assertThat(second.registerEnabled()).isFalse();
        assertThat(third.registerEnabled()).isTrue();
        assertThat(service.getCurrent()).isSameAs(third);
        verify(repository, times(3)).saveAndFlush(any(AuthSetting.class));
    }

    @Test
    void concurrentDatabaseUpdateFailureDoesNotChangeCache() {
        var existing = initializeExisting();
        var previous = service.getCurrent();
        when(repository.saveAndFlush(any(AuthSetting.class)))
                .thenThrow(new ObjectOptimisticLockingFailureException(AuthSetting.class, 1L));

        assertThatThrownBy(() -> service.update(command(0)))
                .isInstanceOf(ObjectOptimisticLockingFailureException.class);

        assertThat(service.getCurrent()).isSameAs(previous);
        assertThat(previous.loginEnabled()).isTrue();
    }

    @Test
    void failedCommitDoesNotPublishUncommittedSettings() throws Exception {
        var existing = initializeExisting();
        var previous = service.getCurrent();
        doThrow(new SQLException("simulated commit failure")).when(connection).commit();

        assertThatThrownBy(() -> service.update(command(0))).isInstanceOf(TransactionSystemException.class);

        assertThat(service.getCurrent()).isSameAs(previous);
        assertThat(events("Auth settings updated:")).isEmpty();
    }

    @Test
    void outerTransactionRollbackDoesNotChangeCache() throws Exception {
        var existing = initializeExisting();
        var previous = service.getCurrent();

        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            service.update(command(0));
            assertThat(service.getCurrent()).isSameAs(previous);
            status.setRollbackOnly();
        });

        assertThat(service.getCurrent()).isSameAs(previous);
        verify(connection).rollback();
        assertThat(events("Auth settings updated:")).isEmpty();
    }

    @Test
    void reloadUpdatesCacheButCannotReplaceANewerVersionWithAnOlderSnapshot() {
        initializeExisting();
        when(repository.findFirstByOrderByVersionDescIdDesc()).thenReturn(Optional.of(setting(3)));
        service.reload();
        assertThat(service.getCurrent().version()).isEqualTo(3);

        when(repository.findFirstByOrderByVersionDescIdDesc()).thenReturn(Optional.of(setting(2)));
        service.reload();
        assertThat(service.getCurrent().version()).isEqualTo(3);
        assertThat(events("Auth settings reloaded:")).hasSize(1);
        assertThat(events("Auth settings reloaded:").getFirst().getFormattedMessage()).contains("version=3");
    }

    @Test
    void invalidUpdateCannotChangeSettings() {
        initializeExisting();
        var previous = service.getCurrent();

        assertThatThrownBy(() -> service.update(AuthSettingDto.builder().id(1)
                .version(0).build())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.update(AuthSettingDto.builder().id(1)
                .version(-1).defaultOtpChannel(OtpChannel.EMAIL).build()))
                .isInstanceOf(IllegalArgumentException.class);

        verify(repository, never()).saveAndFlush(any());
        assertThat(service.getCurrent()).isSameAs(previous);
    }

    @Test
    void databaseFailureIsNotTreatedAsAMissingRecord() {
        when(repository.findFirstByOrderByVersionDescIdDesc())
                .thenThrow(new DataAccessResourceFailureException("simulated outage"));

        assertThatThrownBy(service::initialize).isInstanceOf(DataAccessResourceFailureException.class);

        verify(repository, never()).saveAndFlush(any());
        assertThatThrownBy(service::getCurrent).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void reloadDoesNotRecreateADeletedRecordOrDiscardTheLastKnownSnapshot() {
        initializeExisting();
        var previous = service.getCurrent();
        when(repository.findFirstByOrderByVersionDescIdDesc()).thenReturn(Optional.empty());

        assertThatThrownBy(service::reload).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("missing");

        assertThat(service.getCurrent()).isSameAs(previous);
        verify(repository, never()).saveAndFlush(any());
    }

    private List<ILoggingEvent> events(String prefix) {
        return logs.list.stream().filter(event -> event.getFormattedMessage().startsWith(prefix)).toList();
    }

    private AuthSetting initializeExisting() {
        var existing = setting(0);
        when(repository.findFirstByOrderByVersionDescIdDesc()).thenReturn(Optional.of(existing));
        service.initialize();
        return existing;
    }

    private AuthSetting setting(long version) {
        var setting = new AuthSetting();
        ReflectionTestUtils.setField(setting, "id", 1L);
        ReflectionTestUtils.setField(setting, "version", version);
        ReflectionTestUtils.setField(setting, "updatedAt", Instant.parse("2026-11-01T12:00:00Z"));
        return setting;
    }

    private AuthSettingDto command(long version) {
        return AuthSettingDto.builder().id(1)
                .version(version)
                .loginEnabled(false)
                .registerEnabled(true)
                .defaultOtpChannel(OtpChannel.SMS)
                .emailNotificationEnabled(true)
                .smsNotificationEnabled(false)
                .inAppNotificationEnabled(true)
                .build();
    }

    private static <T> T interfaceMock(Class<T> type) {
        return mock(type);
    }
}
