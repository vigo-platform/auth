package ir.vigoapp.auth.service;

import ir.vigoapp.auth.model.OtpChannel;
import org.springframework.stereotype.Service;

@Service
public class NotificationService {
    public void sendLoginOtp(long userId, OtpChannel channel, String destination, String code) {
    }
}
