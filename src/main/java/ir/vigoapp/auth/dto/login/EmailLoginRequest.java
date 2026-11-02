package ir.vigoapp.auth.dto.login;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailLoginRequest(@NotBlank @Email @Size(max = 254) String email) {}
