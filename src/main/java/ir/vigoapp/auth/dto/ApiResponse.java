package ir.vigoapp.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.time.Instant;

/** Standard response envelope shared by application endpoints. */
@Builder
public record ApiResponse<T>(
        boolean success,
        @JsonInclude(JsonInclude.Include.NON_NULL) String code,
        String message,
        @JsonProperty("message_fa") String messageFa,
        T data,
        String timestamp
) {
    public static <T> ApiResponse<T> success(String message, String messageFa, T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .messageFa(messageFa)
                .data(data)
                .timestamp(Instant.now().toString())
                .build();
    }
}
