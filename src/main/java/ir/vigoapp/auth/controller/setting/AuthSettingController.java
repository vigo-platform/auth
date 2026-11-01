package ir.vigoapp.auth.controller.setting;

import ir.vigoapp.auth.dto.ApiResponse;
import ir.vigoapp.auth.dto.setting.AuthSettingResponse;
import ir.vigoapp.auth.service.AuthSettingService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/settings")
@RequiredArgsConstructor
public class AuthSettingController {

    private final AuthSettingService authSettingService;

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public ApiResponse<AuthSettingResponse> getSettings() {
        return ApiResponse.success(
                "Auth settings retrieved successfully.",
                "تنظیمات احراز هویت با موفقیت دریافت شد.",
                AuthSettingResponse.from(authSettingService.getCurrent()));
    }
}
