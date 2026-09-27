package com.github.lisama569.supplychainadmissiongatejava.web;

import com.github.lisama569.supplychainadmissiongatejava.common.GateException;
import com.github.lisama569.supplychainadmissiongatejava.common.RejectionReason;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/** 领域异常到 HTTP 状态的统一映射，保证拒绝原因可区分、不外泄堆栈。 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(GateException.class)
    public ResponseEntity<Map<String, String>> handleGate(GateException ex) {
        HttpStatus status = status(ex.reason());
        return ResponseEntity.status(status).body(Map.of(
                "reason", ex.reason().name(),
                "message", ex.getMessage() == null ? "" : ex.getMessage()));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> handleUnreadable(HttpMessageNotReadableException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "reason", RejectionReason.MALFORMED_DOCUMENT.name(),
                "message", "请求体不是合法 JSON"));
    }

    static HttpStatus status(RejectionReason reason) {
        return switch (reason) {
            case FORBIDDEN -> HttpStatus.FORBIDDEN;
            case NOT_FOUND, POLICY_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case POLICY_VERSION_CONFLICT, DUPLICATE_CONFLICT -> HttpStatus.CONFLICT;
            default -> HttpStatus.BAD_REQUEST;
        };
    }
}
