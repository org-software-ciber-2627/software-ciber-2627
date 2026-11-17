package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.services.EventStorageUnavailableException;
import com.ciberurjc.siem.services.InvalidHistoryQueryException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.Map;

@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes = EventHistoryController.class)
public class EventHistoryErrorHandler {
    @ExceptionHandler(InvalidHistoryQueryException.class)
    public ResponseEntity<Map<String, Object>> invalidQuery(InvalidHistoryQueryException exception) {
        return error(400, "VALIDATION_ERROR", "Invalid history query parameters");
    }

    @ExceptionHandler(EventStorageUnavailableException.class)
    public ResponseEntity<Map<String, Object>> unavailable(EventStorageUnavailableException exception) {
        return error(503, "STORAGE_UNAVAILABLE", "Event storage is temporarily unavailable");
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> unexpected(RuntimeException exception) {
        return error(500, "INTERNAL_ERROR", "Event history could not be retrieved");
    }

    private ResponseEntity<Map<String, Object>> error(int status, String code, String message) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
            .body(Map.of("error", Map.of("code", code, "message", message)));
    }
}
