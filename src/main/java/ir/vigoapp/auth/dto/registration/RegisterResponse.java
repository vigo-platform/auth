package ir.vigoapp.auth.dto.registration;

import ir.vigoapp.auth.client.user.model.UserAccount;
import lombok.Builder;

/** Account creation does not verify contacts, activate the account, or issue login tokens. */
@Builder
public record RegisterResponse(long userId, UserAccount.AccountStatus status) {
}
