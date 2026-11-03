package ir.vigoapp.auth.dto.login;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Builder;

@Builder
public record PhoneLoginRequest(
        @NotBlank @Pattern(regexp = "(?:\\+[1-9][0-9]{1,14}|(?:0098|0)?9[0-9]{9})",
                message = "Use an Iranian mobile number or an international number starting with +.") String phone
) {}
