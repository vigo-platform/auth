package ir.vigoapp.auth.exception;

import ir.vigoapp.auth.client.user.exception.UserClientException;
import ir.vigoapp.auth.dto.ApiResponse;
import ir.vigoapp.auth.service.login.ClientInfo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.event.Level;
import org.springframework.dao.DataAccessException;
import org.springframework.http.*;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ApiResponse<?>> authentication(AuthException exception, HttpServletRequest request) {
        var client = ClientInfo.from(request);
        log.atWarn().addKeyValue("event", "auth_request_rejected").addKeyValue("result", "REJECTED")
                .addKeyValue("reason", exception.getCode()).addKeyValue("status", exception.getStatus().value())
                .addKeyValue("retry_after_seconds", exception.getRetryAfterSeconds())
                .addKeyValue("http_method", request.getMethod()).addKeyValue("path", request.getRequestURI())
                .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                .addKeyValue("device_id", client.deviceId()).log("Authentication request rejected.");
        var builder = ResponseEntity.status(exception.getStatus()).cacheControl(CacheControl.noStore());
        Object data = null;
        if (exception.getRetryAfterSeconds() > 0) {
            builder.header(HttpHeaders.RETRY_AFTER, Long.toString(exception.getRetryAfterSeconds()));
            data = Map.of("retryAfterSeconds", exception.getRetryAfterSeconds());
        }
        return builder.body(ApiResponse.failure(exception.getCode(), exception.getMessage(), exception.getMessageFa(), data));
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, ConstraintViolationException.class,
            HttpMessageNotReadableException.class, HandlerMethodValidationException.class})
    public ResponseEntity<ApiResponse<?>> invalidRequest(Exception exception, HttpServletRequest request) {
        // Never include rejected values or parser/validation exception text: these may contain credentials.
        return failure(request, exception, HttpStatus.BAD_REQUEST, "INVALID_REQUEST", "The request is invalid.", "اطلاعات درخواست معتبر نیست.");
    }

    @ExceptionHandler(UserClientException.class)
    public ResponseEntity<ApiResponse<?>> userService(UserClientException exception, HttpServletRequest request) {
        return failure(request, exception, HttpStatus.SERVICE_UNAVAILABLE, "AUTH_SERVICE_UNAVAILABLE",
                "Authentication is temporarily unavailable.", "سرویس احراز هویت موقتاً در دسترس نیست.");
    }

    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<ApiResponse<?>> storage(DataAccessException exception, HttpServletRequest request) {
        return failure(request, exception, HttpStatus.SERVICE_UNAVAILABLE, "AUTH_SERVICE_UNAVAILABLE",
                "Authentication is temporarily unavailable.", "سرویس احراز هویت موقتاً در دسترس نیست.");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiResponse<?>> accessDenied(AccessDeniedException exception, HttpServletRequest request) {
        return failure(request, exception, HttpStatus.FORBIDDEN, "ACCESS_DENIED", "Access is denied.", "دسترسی مجاز نیست.");
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiResponse<?>> unauthorized(AuthenticationException exception, HttpServletRequest request) {
        return failure(request, exception, HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication is required.", "احراز هویت الزامی است.");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ApiResponse<?>> methodNotAllowed(HttpRequestMethodNotSupportedException exception, HttpServletRequest request) {
        return failure(request, exception, HttpStatus.METHOD_NOT_ALLOWED, "METHOD_NOT_ALLOWED", "The HTTP method is not allowed.", "متد درخواست مجاز نیست.");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ApiResponse<?>> unsupportedMediaType(HttpMediaTypeNotSupportedException exception, HttpServletRequest request) {
        return failure(request, exception, HttpStatus.UNSUPPORTED_MEDIA_TYPE, "UNSUPPORTED_MEDIA_TYPE", "Use an application/json request body.", "بدنه درخواست باید JSON باشد.");
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ApiResponse<?>> notFound(NoResourceFoundException exception, HttpServletRequest request) {
        return failure(request, exception, HttpStatus.NOT_FOUND, "NOT_FOUND", "The endpoint does not exist.", "مسیر درخواست یافت نشد.");
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<?>> unexpected(Exception exception, HttpServletRequest request) {
        return failure(request, exception, HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR", "An unexpected error occurred.", "خطای غیرمنتظره رخ داد.");
    }

    private ResponseEntity<ApiResponse<?>> failure(HttpServletRequest request, Exception exception, HttpStatus status,
                                                  String code, String message, String messageFa) {
        var client = ClientInfo.from(request);
        log.atLevel(status.is5xxServerError() ? Level.ERROR : Level.WARN)
                .addKeyValue("event", "auth_request_failed").addKeyValue("result", "FAILURE")
                .addKeyValue("status", status.value()).addKeyValue("error_code", code)
                .addKeyValue("reason", exception instanceof UserClientException remote ? remote.getCode() : exception.getClass().getSimpleName())
                .addKeyValue("operation", exception instanceof UserClientException remote ? remote.getOperation() : null)
                .addKeyValue("http_method", request.getMethod()).addKeyValue("path", request.getRequestURI())
                .addKeyValue("ip_address", client.ipAddress()).addKeyValue("user_agent", client.userAgent())
                .addKeyValue("device_id", client.deviceId()).log("Request could not be completed.");
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore()).body(ApiResponse.failure(code, message, messageFa, null));
    }
}
