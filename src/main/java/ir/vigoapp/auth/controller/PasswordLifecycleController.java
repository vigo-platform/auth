package ir.vigoapp.auth.controller;

import ir.vigoapp.auth.dto.ApiResponse;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.login.LoginResponse;
import ir.vigoapp.auth.dto.password.PasswordChangeCompleteRequest;
import ir.vigoapp.auth.dto.password.PasswordChangeInitiateRequest;
import ir.vigoapp.auth.dto.password.PasswordResetCompleteRequest;
import ir.vigoapp.auth.dto.password.PasswordResetInitiateRequest;
import ir.vigoapp.auth.dto.password.PasswordStepResponse;
import ir.vigoapp.auth.dto.password.PasswordVerifyRequest;
import ir.vigoapp.auth.service.PasswordLifecycleService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth/password")
@RequiredArgsConstructor
public class PasswordLifecycleController {
    private final PasswordLifecycleService passwords;

    @PostMapping("/expired/complete")
    public ApiResponse<LoginResponse> completeExpired(@Valid @RequestBody PasswordChangeCompleteRequest body,
                                                       HttpServletRequest request) {
        return LoginController.loginResponse(passwords.completeExpired(body.passwordChangeToken(), body.newPassword(),
                ClientInfo.from(request)));
    }

    @PostMapping("/change/initiate")
    public ApiResponse<PasswordStepResponse> initiateChange(@AuthenticationPrincipal Jwt jwt,
                                                             @Valid @RequestBody PasswordChangeInitiateRequest body,
                                                             HttpServletRequest request) {
        return response(passwords.initiateChange(jwt, body.currentPassword(), ClientInfo.from(request)));
    }

    @PostMapping("/change/verify")
    public ApiResponse<PasswordStepResponse> verifyChange(@AuthenticationPrincipal Jwt jwt,
                                                          @Valid @RequestBody PasswordVerifyRequest body,
                                                          HttpServletRequest request) {
        return response(passwords.verifyChange(jwt, body.mfaToken(), body.otp(), ClientInfo.from(request)));
    }

    @PostMapping("/change/complete")
    public ApiResponse<PasswordStepResponse> completeChange(@AuthenticationPrincipal Jwt jwt,
                                                            @Valid @RequestBody PasswordChangeCompleteRequest body,
                                                            HttpServletRequest request) {
        return response(passwords.completeChange(jwt, body.passwordChangeToken(), body.newPassword(),
                ClientInfo.from(request)));
    }

    @PostMapping("/reset/initiate")
    public ApiResponse<PasswordStepResponse> initiateReset(@Valid @RequestBody PasswordResetInitiateRequest body,
                                                           HttpServletRequest request) {
        return ApiResponse.success("If the account is eligible, a verification code will be sent.",
                "در صورت امکان بازیابی حساب، کد تأیید ارسال می‌شود.",
                passwords.initiateReset(body.identifier(), ClientInfo.from(request)));
    }

    @PostMapping("/reset/verify")
    public ApiResponse<PasswordStepResponse> verifyReset(@Valid @RequestBody PasswordVerifyRequest body,
                                                         HttpServletRequest request) {
        return response(passwords.verifyReset(body.mfaToken(), body.otp(), ClientInfo.from(request)));
    }

    @PostMapping("/reset/complete")
    public ApiResponse<PasswordStepResponse> completeReset(@Valid @RequestBody PasswordResetCompleteRequest body,
                                                            HttpServletRequest request) {
        return response(passwords.completeReset(body.passwordResetToken(), body.newPassword(), ClientInfo.from(request)));
    }

    private static ApiResponse<PasswordStepResponse> response(PasswordStepResponse result) {
        return switch (result.step()) {
            case "OTP_REQUIRED" -> ApiResponse.success("Enter the verification code.",
                    "کد تأیید را وارد کنید.", result);
            case "PASSWORD_CHANGE_REQUIRED", "PASSWORD_RESET_REQUIRED" -> ApiResponse.success(
                    "Set a new password.", "رمز عبور جدید را تعیین کنید.", result);
            case "PASSWORD_UPDATED_LOGIN_REQUIRED" -> ApiResponse.success(
                    "Password updated. Sign in with your new password.",
                    "رمز عبور تغییر کرد. با رمز جدید وارد شوید.", result);
            default -> throw new IllegalStateException("Unexpected password lifecycle step");
        };
    }
}
