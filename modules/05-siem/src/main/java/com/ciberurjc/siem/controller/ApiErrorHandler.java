package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.config.RequestBodyTooLargeException;
import com.ciberurjc.siem.services.AlertConflictException;
import com.ciberurjc.siem.services.AlertStorageFullException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.Map;

@RestControllerAdvice
public class ApiErrorHandler {
    private static final Logger logger = LoggerFactory.getLogger(ApiErrorHandler.class);

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> invalidJson(HttpMessageNotReadableException exception) {
        if (hasCause(exception, RequestBodyTooLargeException.class)) {
            return payloadTooLarge();
        }
        return error(400, "INVALID_JSON", "The body must match the JSON event structure");
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, IllegalArgumentException.class})
    public ResponseEntity<Map<String, Object>> invalidEvent(Exception exception) {
        return error(400, "VALIDATION_ERROR", "The event does not match the required schema");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> unsupportedMediaType(HttpMediaTypeNotSupportedException exception) {
        return error(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json");
    }

    @ExceptionHandler(AlertConflictException.class)
    public ResponseEntity<Map<String, Object>> eventConflict(AlertConflictException exception) {
        logger.warn("Rejected event with changed content for existing alert: alert_id={}", exception.alertId());
        return error(409, "EVENT_CONFLICT",
            "An event with the same source and event_id was already received with different content");
    }

    @ExceptionHandler(AlertStorageFullException.class)
    public ResponseEntity<Map<String, Object>> storageFull(AlertStorageFullException exception) {
        logger.warn("Rejected event because alert storage is full");
        return error(507, "STORAGE_FULL", "Alert storage has reached its capacity");
    }

    private ResponseEntity<Map<String, Object>> payloadTooLarge() {
        return error(413, "PAYLOAD_TOO_LARGE", "The request body exceeds the maximum allowed size");
    }

    private static boolean hasCause(Throwable exception, Class<? extends Throwable> type) {
        // Bounded walk guards against cyclic cause chains.
        Throwable current = exception;
        for (int depth = 0; current != null && depth < 16; depth++, current = current.getCause()) {
            if (type.isInstance(current)) {
                return true;
            }
        }
        return false;
    }

    private ResponseEntity<Map<String, Object>> error(int status, String code, String message) {
        return ResponseEntity.status(status).body(Map.of("error", Map.of("code", code, "message", message)));
    }
}
