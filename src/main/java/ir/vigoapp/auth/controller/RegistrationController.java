package ir.vigoapp.auth.controller;

import ir.vigoapp.auth.dto.ApiResponse;
import ir.vigoapp.auth.dto.ClientInfo;
import ir.vigoapp.auth.dto.registration.RegisterRequest;
import ir.vigoapp.auth.dto.registration.RegisterResponse;
import ir.vigoapp.auth.dto.registration.RegistrationInitiateRequest;
import ir.vigoapp.auth.dto.registration.RegistrationInitiateResponse;
import ir.vigoapp.auth.dto.registration.RegistrationVerifyRequest;
import ir.vigoapp.auth.dto.registration.RegistrationVerifyResponse;
import ir.vigoapp.auth.service.RegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class RegistrationController {
    private final RegistrationService registration;

    @PostMapping("/register/initiate")
    public ApiResponse<RegistrationInitiateResponse> initiate(@Valid @RequestBody RegistrationInitiateRequest body,
                                                            HttpServletRequest request) {
        return ApiResponse.success("Registration verification code requested.", "درخواست کد تأیید ثبت‌نام انجام شد.",
                registration.initiate(body, ClientInfo.from(request)));
    }

    @PostMapping("/register/verify")
    public ApiResponse<RegistrationVerifyResponse> verify(@Valid @RequestBody RegistrationVerifyRequest body,
                                                        HttpServletRequest request) {
        return ApiResponse.success("Contact verified. Complete your registration.", "اطلاعات تماس تأیید شد. ثبت‌نام را تکمیل کنید.",
                registration.verify(body, ClientInfo.from(request)));
    }

    @PostMapping({"/register", "/register/complete"})
    @ResponseStatus(HttpStatus.CREATED)
    public ApiResponse<RegisterResponse> complete(@Valid @RequestBody RegisterRequest body, HttpServletRequest request) {
        return ApiResponse.success("Account created successfully.", "حساب کاربری با موفقیت ایجاد شد.",
                registration.register(body, ClientInfo.from(request)));
    }
}
