package ir.vigoapp.auth.service;

import ir.vigoapp.auth.model.OtpChannel;
import org.springframework.stereotype.Service;

@Service
public class NotificationService {
    public void sendLoginOtp(long userId, OtpChannel channel, String destination, String code) {
    }

    /** Guest delivery boundary: connect the notification transport here, without logging the payload. */
    public void sendRegistrationOtp(OtpChannel channel, String destination, String code) {

    }

    /** Delivery boundaries for password operations. Route by purpose in the notification transport. */
    public void sendPasswordChangeOtp(long userId, OtpChannel channel, String destination, String code) {
    }

    public void sendPasswordResetOtp(long userId, OtpChannel channel, String destination, String code) {
    }

    public void sendPasswordResetNotice(long userId) {
    }
}
