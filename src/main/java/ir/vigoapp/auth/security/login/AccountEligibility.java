package ir.vigoapp.auth.security.login;

import ir.vigoapp.auth.client.user.model.UserAccount;
import ir.vigoapp.auth.model.OtpChannel;

public final class AccountEligibility {
    private AccountEligibility() {}

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
