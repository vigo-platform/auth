package ir.vigoapp.auth.bootstrap;

import ir.vigoapp.auth.service.AuthSettingService;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Initializes auth settings before the application is marked ready.
 *
 * @version 1.0.0
 * @author logTAHA
 */
@Component
@RequiredArgsConstructor
public class AuthSettingInitializer implements ApplicationRunner {

    private final AuthSettingService service;

    @Override
    public void run(@NonNull ApplicationArguments args) {
        service.initialize();
    }
}
