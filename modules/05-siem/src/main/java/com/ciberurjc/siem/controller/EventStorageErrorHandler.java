package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.services.EventIdConflictException;
import com.ciberurjc.siem.services.EventStorageUnavailableException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class EventStorageErrorHandler {
    @ExceptionHandler(EventIdConflictException.class)
    public ResponseEntity<Map<String, Object>> conflict(EventIdConflictException exception) {
        return ResponseEntity.status(409).body(Map.of("error", Map.of(
            "code", "EVENT_ID_CONFLICT", "message", exception.getMessage())));
    }

    @ExceptionHandler(EventStorageUnavailableException.class)
    public ResponseEntity<Map<String, Object>> unavailable(EventStorageUnavailableException exception) {
        return ResponseEntity.status(503).body(Map.of("error", Map.of(
            "code", "STORAGE_UNAVAILABLE", "message", exception.getMessage())));
    }
}
