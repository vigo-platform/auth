package ir.vigoapp.auth.security.login;

import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.model.OtpChannel;

public final class AccountEligibility {
    private AccountEligibility() {}

    // TODO(credentials-expiry): After the registration/change-password flows are ready, separate
    // active-account eligibility from final credential validity. Expiry must not reject password
    // verification or login OTP issuance/delivery (including the password follow-up for 2FA).
    // Keep status, verified-contact and 2FA checks; handle expiry after all required factors pass,
    // at SessionService.create(), before issuing a normal session. Keep refresh protected.
    // Retain the current expiry gate until that password-change continuation is implemented.
    public static boolean canLogin(UserAccount user) {
        return user.status() == UserAccount.AccountStatus.ACTIVE && !user.credentialsExpired();
    }

    public static boolean canReceiveOtp(UserAccount user, OtpChannel channel) {
        return canLogin(user) && switch (channel) {
            case EMAIL -> user.emailVerified() && user.email() != null && !user.email().isBlank();
            case SMS -> user.phoneVerified() && user.phone() != null && !user.phone().isBlank();
            case IN_APP -> true;
        };
    }

    public static String destination(UserAccount user, OtpChannel channel) {
        return switch (channel) {
            case EMAIL -> user.email();
            case SMS -> user.phone();
            case IN_APP -> Long.toString(user.userId());
        };
    }
}
