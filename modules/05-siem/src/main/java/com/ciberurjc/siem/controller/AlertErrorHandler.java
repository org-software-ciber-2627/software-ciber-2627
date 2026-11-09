package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.services.AlertStorageUnavailableException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.Map;

@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = AlertController.class)
public class AlertErrorHandler {
    @ExceptionHandler(AlertStorageUnavailableException.class)
    public ResponseEntity<Map<String, Object>> storageUnavailable(AlertStorageUnavailableException exception) {
        return error(503, "STORAGE_UNAVAILABLE", "Alert storage is temporarily unavailable");
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> unexpectedFailure(RuntimeException exception) {
        return error(500, "INTERNAL_ERROR", "An unexpected error occurred");
    }

    private ResponseEntity<Map<String, Object>> error(int status, String code, String message) {
        return ResponseEntity.status(status).body(Map.of("error", Map.of("code", code, "message", message)));
    }
}
