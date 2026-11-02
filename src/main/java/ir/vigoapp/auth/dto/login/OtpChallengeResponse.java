package ir.vigoapp.auth.dto.login;

import ir.vigoapp.auth.entity.OtpChannel;

public record OtpChallengeResponse(String mfaToken, OtpChannel channel, long expiresIn, long resendAfter) {
    @Override
    public String toString() { return "OtpChallengeResponse[REDACTED]"; }
}
