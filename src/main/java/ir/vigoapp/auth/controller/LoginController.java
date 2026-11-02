package ir.vigoapp.auth.controller;

import ir.vigoapp.auth.dto.ApiResponse;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.login.EmailLoginRequest;
import ir.vigoapp.auth.dto.login.LoginResponse;
import ir.vigoapp.auth.dto.login.PasswordLoginRequest;
import ir.vigoapp.auth.dto.login.PhoneLoginRequest;
import ir.vigoapp.auth.dto.login.VerifyLoginRequest;
import ir.vigoapp.auth.dto.registration.RegisterRequest;
import ir.vigoapp.auth.dto.registration.RegisterResponse;
import ir.vigoapp.auth.dto.token.RefreshRequest;
import ir.vigoapp.auth.dto.token.TokenResponse;
import ir.vigoapp.auth.model.OtpChannel;
import ir.vigoapp.auth.service.LoginService;
import ir.vigoapp.auth.service.RegistrationService;
import ir.vigoapp.auth.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Slf4j
public class LoginController {
    private final LoginService login;
    private final SessionService sessions;
    private final RegistrationService registration;

    @ModelAttribute
    public void prepareRequest(HttpServletRequest request, HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader(HttpHeaders.PRAGMA, "no-cache");
        var client = ClientInfo.from(request);
        log.atInfo().addKeyValue("event", "auth_request_received")
                .addKeyValue("http_method", request.getMethod()).addKeyValue("path", request.getRequestURI())
                .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                .addKeyValue("device_id", client.deviceId()).log("Authentication request received.");
    }

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    public ApiResponse<RegisterResponse> register(@Valid @RequestBody RegisterRequest body, HttpServletRequest request) {
        return ApiResponse.success("Account created successfully.", "حساب کاربری با موفقیت ایجاد شد.",
                registration.register(body, ClientInfo.from(request)));
    }

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
    public ApiResponse<Void> logout(@Valid @RequestBody RefreshRequest body, HttpServletRequest request) {
        sessions.logout(body.refreshToken(), ClientInfo.from(request));
        return ApiResponse.success("Logged out successfully.", "خروج با موفقیت انجام شد.", null);
    }

    @PostMapping("/logout-all")
    public ApiResponse<Void> logoutAll(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request) {
        sessions.logoutAll(Long.parseLong(jwt.getSubject()), ClientInfo.from(request));
        return ApiResponse.success("All sessions logged out successfully.", "خروج از همه نشست‌ها انجام شد.", null);
    }

    private static ApiResponse<LoginResponse> loginResponse(LoginResponse result) {
        return result.challenge() == null
                ? ApiResponse.success("Logged in successfully.", "ورود با موفقیت انجام شد.", result)
                : ApiResponse.success("If the account is eligible, a verification code will be sent.",
                        "در صورت امکان ورود به حساب، کد تأیید ارسال می‌شود.", result);
    }
}
