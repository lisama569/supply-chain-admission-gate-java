package com.github.lisama569.supplychainadmissiongatejava.web;

import com.github.lisama569.supplychainadmissiongatejava.ingest.IngestException;
import com.github.lisama569.supplychainadmissiongatejava.service.PermissionDeniedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(PermissionDeniedException.class)
    public ResponseEntity<Map<String, Object>> permissionDenied(PermissionDeniedException e) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(Map.of("reason", e.reason().name(), "message", e.getMessage()));
    }

    @ExceptionHandler(IngestException.class)
    public ResponseEntity<Map<String, Object>> ingestRejected(IngestException e) {
        return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(Map.of("reason", e.reason().name(), "message", e.getMessage()));
    }
}
