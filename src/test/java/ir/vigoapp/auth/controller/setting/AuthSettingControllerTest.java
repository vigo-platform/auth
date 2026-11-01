package ir.vigoapp.auth.controller.setting;

import ir.vigoapp.auth.dto.setting.AuthSettingDto;
import ir.vigoapp.auth.entity.OtpChannel;
import ir.vigoapp.auth.service.AuthSettingService;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Instant;

import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.matchesPattern;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AuthSettingControllerTest {

    @Test
    void returnsCurrentSettingsInStandardEnvelope() throws Exception {
        var settings = AuthSettingDto.builder()
                .id(12).version(3).updatedAt(Instant.parse("2026-10-18T18:30:00Z"))
                .loginEnabled(true).registerEnabled(false).defaultOtpChannel(OtpChannel.EMAIL)
                .emailNotificationEnabled(true).smsNotificationEnabled(false)
                .inAppNotificationEnabled(true).build();
        var service = new AuthSettingService(null, null) {
            @Override
            public AuthSettingDto getCurrent() {
                return settings;
            }
        };
        var mvc = MockMvcBuilders.standaloneSetup(new AuthSettingController(service)).build();

        mvc.perform(get("/api/v1/auth/settings").accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$", aMapWithSize(5)))
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.code").doesNotHaveJsonPath())
                .andExpect(jsonPath("$.message").value("Auth settings retrieved successfully."))
                .andExpect(jsonPath("$.message_fa").value("تنظیمات احراز هویت با موفقیت دریافت شد."))
                .andExpect(jsonPath("$.timestamp", matchesPattern("\\d{4}-\\d{2}-\\d{2}T.*Z")))
                .andExpect(jsonPath("$.data", aMapWithSize(6)))
                .andExpect(jsonPath("$.data.id").doesNotHaveJsonPath())
                .andExpect(jsonPath("$.data.version").doesNotHaveJsonPath())
                .andExpect(jsonPath("$.data.updatedAt").doesNotHaveJsonPath())
                .andExpect(jsonPath("$.data.loginEnabled").value(true))
                .andExpect(jsonPath("$.data.registerEnabled").value(false))
                .andExpect(jsonPath("$.data.defaultOtpChannel").value("EMAIL"))
                .andExpect(jsonPath("$.data.emailNotificationEnabled").value(true))
                .andExpect(jsonPath("$.data.smsNotificationEnabled").value(false))
                .andExpect(jsonPath("$.data.inAppNotificationEnabled").value(true));

    }
}
