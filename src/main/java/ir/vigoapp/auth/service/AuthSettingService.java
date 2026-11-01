package ir.vigoapp.auth.service;

import ir.vigoapp.auth.config.ApplicationProperties;
import ir.vigoapp.auth.entity.AuthSetting;
import ir.vigoapp.auth.repository.AuthSettingRepository;
import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Initializes and caches the latest auth settings revision, appending a new row for each change.
 * Cache changes become visible only after a successful database commit.
 *
 * @version 1.0.0
 * @author logTAHA
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AuthSettingService {

    private final AuthSettingRepository repository;
    private final ApplicationProperties properties;
    private final AtomicReference<AuthSettingDto> cached = new AtomicReference<>();

    /** Creates missing settings from configuration, preserving any existing record. */
    @Transactional
    public AuthSettingDto initialize() {
        repository.lockForRevisionChange();
        var existing = repository.findFirstByOrderByVersionDescIdDesc();
        if (existing.isPresent()) {
            return cacheAfterCommit(existing.get(), "loaded");
        }
        return cacheAfterCommit(createInitialSettings(), "created from defaults");
    }

    private AuthSetting createInitialSettings() {
        var defaults = properties.getAuthDefaults();
        Assert.notNull(defaults.getDefaultOtpChannel(), "Default OTP channel is required");
        var setting = AuthSetting.builder()
                .version(1)
                .loginEnabled(defaults.isLoginEnabled())
                .registerEnabled(defaults.isRegisterEnabled())
                .defaultOtpChannel(defaults.getDefaultOtpChannel())
                .emailNotificationEnabled(defaults.isEmailNotificationEnabled())
                .smsNotificationEnabled(defaults.isSmsNotificationEnabled())
                .inAppNotificationEnabled(defaults.isInAppNotificationEnabled())
                .build();
        return repository.saveAndFlush(setting);
    }

    /** Reads the local snapshot without querying the database. */
    public AuthSettingDto getCurrent() {
        var snapshot = cached.get();
        if (snapshot == null) {
            throw new IllegalStateException("Auth settings have not been initialized");
        }
        return snapshot;
    }

    /** Reloads the local cache after a database change made outside this service. */
    @Transactional(readOnly = true)
    public AuthSettingDto reload() {
        return cacheAfterCommit(requireSettings(), "reloaded");
    }

    /** Appends a revision; callers must authorize administration before invoking this method. */
    @Transactional
    public AuthSettingDto update(AuthSettingDto command) {
        Assert.notNull(command, "command is required");
        Assert.isTrue(command.id() > 0, "id must be positive");
        Assert.isTrue(command.version() >= 0, "version must not be negative");
        Assert.notNull(command.defaultOtpChannel(), "defaultOtpChannel is required");
        repository.lockForRevisionChange();
        var setting = requireSettings();
        if (setting.getVersion() != command.version() || setting.getId() != command.id()) {
            throw new ObjectOptimisticLockingFailureException(AuthSetting.class, setting.getId());
        }

        var revision = AuthSetting.builder()
                .version(Math.incrementExact(setting.getVersion()))
                .loginEnabled(command.loginEnabled())
                .registerEnabled(command.registerEnabled())
                .defaultOtpChannel(command.defaultOtpChannel())
                .emailNotificationEnabled(command.emailNotificationEnabled())
                .smsNotificationEnabled(command.smsNotificationEnabled())
                .inAppNotificationEnabled(command.inAppNotificationEnabled())
                .build();
        return cacheAfterCommit(repository.saveAndFlush(revision), "updated");
    }

    private AuthSetting requireSettings() {
        return repository.findFirstByOrderByVersionDescIdDesc()
                .orElseThrow(() -> new IllegalStateException("Auth settings record is missing"));
    }

    private AuthSettingDto cacheAfterCommit(AuthSetting setting, String action) {
        var snapshot = AuthSettingDto.from(setting);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                // A delayed callback from an older transaction must not replace a newer snapshot.
                var active = cached.updateAndGet(current -> current == null || snapshot.version() >= current.version()
                        ? snapshot : current);
                if (active == snapshot) {
                    log.info("Auth settings {}: id={}, version={}", action, snapshot.id(), snapshot.version());
                }
            }
        });
        return snapshot;
    }

}
