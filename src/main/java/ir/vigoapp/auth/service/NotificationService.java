package ir.vigoapp.auth.service;

import ir.vigoapp.auth.exception.AuthException;
import ir.vigoapp.auth.model.OtpChannel;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
public class NotificationService {
    public void sendLoginOtp(long userId, OtpChannel channel, String destination, String code) {
    }

    /** Guest delivery boundary: connect the notification transport here, without logging the payload. */
    public void sendRegistrationOtp(OtpChannel channel, String destination, String code) {

    }
}
