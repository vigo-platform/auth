package ir.vigoapp.auth.dto.login;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Builder;

@Builder
public record EmailLoginRequest(@NotBlank @Email @Size(max = 254) String email) {}
