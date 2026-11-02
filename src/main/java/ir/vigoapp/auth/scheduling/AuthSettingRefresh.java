package ir.vigoapp.auth.scheduling;

import ir.vigoapp.auth.service.AuthSettingService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthSettingRefresh {
    private final AuthSettingService settings;

    @Scheduled(fixedDelayString = "${app.auth-settings-refresh-interval:PT5S}",
            initialDelayString = "${app.auth-settings-refresh-interval:PT5S}")
    public void refresh() {
        try {
            settings.reload();
        } catch (RuntimeException exception) {
            // Keep the last committed snapshot and retry on the next scheduled run.
            log.atWarn().addKeyValue("event", "auth_settings_refresh_failed")
                    .addKeyValue("reason", exception.getClass().getSimpleName())
                    .log("Auth settings refresh failed; retaining the last committed snapshot.");
        }
    }
}
