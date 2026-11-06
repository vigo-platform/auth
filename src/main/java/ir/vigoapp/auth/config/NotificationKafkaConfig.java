package ir.vigoapp.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.support.ProducerListener;

@Configuration(proxyBeanMethods = false)
public class NotificationKafkaConfig {
    @Bean
    public ProducerListener<Object, Object> kafkaProducerListener() {
        // NotificationService reports failures without including the OTP or recipient.
        return new ProducerListener<>() {};
    }
}
