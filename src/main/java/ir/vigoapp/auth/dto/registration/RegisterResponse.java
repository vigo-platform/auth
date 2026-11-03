package ir.vigoapp.auth.dto.registration;

import com.fasterxml.jackson.annotation.JsonInclude;
import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.dto.token.TokenResponse;
import lombok.Builder;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Builder
public record RegisterResponse(long userId, UserAccount.AccountStatus status, TokenResponse tokens) {
}
