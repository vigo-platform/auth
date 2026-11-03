package ir.vigoapp.auth.dto.registration;

import ir.vigoapp.auth.client.user.model.UserAccount;
import lombok.Builder;

/** User owns activation and verification flags; registration does not issue login tokens. */
@Builder
public record RegisterResponse(long userId, UserAccount.AccountStatus status) {
}
