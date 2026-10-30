package ir.vigoapp.auth.client.user.exception;

import lombok.Getter;

/** Contains only an operation name and safe error code, never a remote description or payload. */
@Getter
public final class UserClientException extends RuntimeException {
    private final Code code;
    private final String operation;

    public UserClientException(Code code, String operation) {
        super("User service " + operation + " failed: " + code);
        this.code = code;
        this.operation = operation;
    }

    public enum Code {
        INVALID_ARGUMENT, NOT_FOUND, ALREADY_EXISTS, CONFLICT, UNAUTHENTICATED,
        PERMISSION_DENIED, UNAVAILABLE, TIMEOUT, CANCELLED, RESOURCE_EXHAUSTED,
        FAILED_PRECONDITION, INVALID_RESPONSE, INTERNAL
    }
}
