package ir.vigoapp.auth.service.notification;

import ir.vigoapp.auth.entity.OtpChannel;
import org.springframework.stereotype.Service;

@Service
public class NotificationService {
    public void sendLoginOtp(long userId, OtpChannel channel, String destination, String code) {
    }
}
