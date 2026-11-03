package ir.vigoapp.auth.controller;

import ir.vigoapp.auth.dto.ApiResponse;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.login.EmailLoginRequest;
import ir.vigoapp.auth.dto.login.LoginResponse;
import ir.vigoapp.auth.dto.login.PasswordLoginRequest;
import ir.vigoapp.auth.dto.login.PhoneLoginRequest;
import ir.vigoapp.auth.dto.login.VerifyLoginRequest;
import ir.vigoapp.auth.dto.token.RefreshRequest;
import ir.vigoapp.auth.dto.token.TokenResponse;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.service.LoginService;
import ir.vigoapp.auth.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class LoginController {
    private final LoginService login;
    private final SessionService sessions;

    @PostMapping("/login-password")
    public ApiResponse<LoginResponse> password(@Valid @RequestBody PasswordLoginRequest body, HttpServletRequest request) {
        var result = login.loginWithPassword(body, ClientInfo.from(request));
        return loginResponse(result);
    }

    @PostMapping("/login-otp-email")
    public ApiResponse<LoginResponse> email(@Valid @RequestBody EmailLoginRequest body, HttpServletRequest request) {
        return loginResponse(login.loginWithOtp(body.email(), OtpChannel.EMAIL, ClientInfo.from(request)));
    }

    @PostMapping("/login-otp-phone")
    public ApiResponse<LoginResponse> phone(@Valid @RequestBody PhoneLoginRequest body, HttpServletRequest request) {
        return loginResponse(login.loginWithOtp(body.phone(), OtpChannel.SMS, ClientInfo.from(request)));
    }

    @PostMapping("/verify")
    public ApiResponse<LoginResponse> verify(@Valid @RequestBody VerifyLoginRequest body, HttpServletRequest request) {
        return loginResponse(login.verify(body, ClientInfo.from(request)));
    }

    @PostMapping("/refresh")
    public ApiResponse<TokenResponse> refresh(@Valid @RequestBody RefreshRequest body, HttpServletRequest request) {
        return ApiResponse.success("Tokens refreshed successfully.", "توکن‌ها با موفقیت تازه‌سازی شدند.",
                sessions.refresh(body.refreshToken(), ClientInfo.from(request)));
    }

    @PostMapping("/logout")
    public ApiResponse<Void> logout(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request) {
        sessions.logout(UUID.fromString(jwt.getClaimAsString("sid")), Long.parseLong(jwt.getSubject()), ClientInfo.from(request));
        return ApiResponse.success("Logged out successfully.", "خروج با موفقیت انجام شد.", null);
    }

    @PostMapping("/logout-all")
    public ApiResponse<Void> logoutAll(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request) {
        sessions.logoutAll(Long.parseLong(jwt.getSubject()), ClientInfo.from(request));
        return ApiResponse.success("All sessions logged out successfully.", "خروج از همه نشست‌ها انجام شد.", null);
    }

    public static ApiResponse<LoginResponse> loginResponse(LoginResponse result) {
        return switch (result.step()) {
            case "SUCCESS" -> ApiResponse.success("Logged in successfully.", "ورود با موفقیت انجام شد.", result);
            case "OTP_REQUIRED" -> ApiResponse.success("If the account is eligible, a verification code will be sent.",
                    "در صورت امکان ورود به حساب، کد تأیید ارسال می‌شود.", result);
            case "PASSWORD_CHANGE_REQUIRED" -> ApiResponse.success("Choose a new password to complete sign-in.",
                    "برای تکمیل ورود، رمز عبور جدید انتخاب کنید.", result);
            case "PASSWORD_UPDATED_LOGIN_REQUIRED" -> ApiResponse.success("Password updated. Please sign in.",
                    "رمز عبور تغییر کرد. لطفاً وارد شوید.", result);
            default -> throw new IllegalStateException("Unknown login response step");
        };
    }
}
