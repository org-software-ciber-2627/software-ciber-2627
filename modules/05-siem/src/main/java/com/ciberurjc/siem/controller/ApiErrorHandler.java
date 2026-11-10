package com.ciberurjc.siem.controller;

import com.ciberurjc.siem.config.RequestBodyTooLargeException;
import com.ciberurjc.siem.exceptions.EventValidationException;
import com.ciberurjc.siem.exceptions.MissingEventBodyException;
import com.ciberurjc.siem.exceptions.UnstorableEventException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import tools.jackson.core.JacksonException;
import tools.jackson.core.exc.InputCoercionException;
import tools.jackson.core.exc.StreamReadException;
import tools.jackson.databind.exc.MismatchedInputException;
import tools.jackson.databind.exc.UnrecognizedPropertyException;
import com.ciberurjc.siem.services.AlertStorageFullException;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

@RestControllerAdvice
public class ApiErrorHandler {
    private static final List<String> EVENT_FIELDS = List.of(
        "event_id", "timestamp", "source", "event_type", "severity", "title", "description", "details");
    private static final String MISSING_BODY_MESSAGE = "The request body is required and must contain a JSON event object";

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> invalidJson(HttpMessageNotReadableException exception) {
        // SEM-72's body limit can be wrapped by the JSON reader, especially for chunked requests.
        var tooLarge = findCause(exception, RequestBodyTooLargeException.class);
        if (tooLarge != null) return payloadTooLarge(tooLarge);
        return error(400, "INVALID_JSON", jsonErrorMessage(exception));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> invalidEvent(MethodArgumentNotValidException exception) {
        var blankFields = exception.getBindingResult().getFieldErrors().stream()
            .filter(fieldError -> "NotBlank".equals(fieldError.getCode()))
            .map(fieldError -> fieldError.getField())
            .collect(Collectors.toSet());
        var errors = new TreeMap<String, TreeSet<String>>();
        for (var fieldError : exception.getBindingResult().getFieldErrors()) {
            // A blank field needs a value before its format can be corrected.
            if ("Pattern".equals(fieldError.getCode()) && blankFields.contains(fieldError.getField())) continue;
            String message = fieldError.getDefaultMessage();
            errors.computeIfAbsent(fieldError.getField(), field -> new TreeSet<>())
                .add(message == null ? "is invalid" : message);
        }
        String message = errors.entrySet().stream()
            .map(entry -> entry.getKey() + ": " + String.join(", ", entry.getValue()))
            .collect(Collectors.joining("; "));
        return error(400, "VALIDATION_ERROR", message.isEmpty()
            ? "The event does not match the required schema" : message);
    }

    @ExceptionHandler(EventValidationException.class)
    public ResponseEntity<Map<String, Object>> invalidEventValue(EventValidationException exception) {
        return error(400, "VALIDATION_ERROR", exception.getMessage());
    }

    @ExceptionHandler(RequestBodyTooLargeException.class)
    public ResponseEntity<Map<String, Object>> payloadTooLarge(RequestBodyTooLargeException exception) {
        return error(413, "PAYLOAD_TOO_LARGE", "The request body exceeds the maximum allowed size");
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> unsupportedMediaType(HttpMediaTypeNotSupportedException exception) {
        return error(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json");
    }

    @ExceptionHandler(AlertStorageFullException.class)
    public ResponseEntity<Map<String, Object>> storageFull(AlertStorageFullException exception) {
        return error(507, "STORAGE_FULL", "Alert storage has reached its capacity");
    }

    @ExceptionHandler(UnstorableEventException.class)
    public ResponseEntity<Map<String, Object>> unstorableEvent(UnstorableEventException exception) {
        return error(400, "VALIDATION_ERROR", "The event does not match the required schema");
    }

    private String jsonErrorMessage(HttpMessageNotReadableException exception) {
        if (exception instanceof MissingEventBodyException) {
            return MISSING_BODY_MESSAGE;
        }
        // InputCoercionException is a StreamReadException, but need not mean invalid syntax.
        var coercion = findCause(exception, InputCoercionException.class);
        if (coercion != null) {
            return conversionMessage(coercion);
        }
        if (findCause(exception, StreamReadException.class) != null) {
            return "Malformed JSON: check the request body syntax";
        }
        var unknownProperty = findCause(exception, UnrecognizedPropertyException.class);
        if (unknownProperty != null) {
            // Even a short, ordinary-looking property name can contain a secret.
            return "The event contains an unknown field; allowed fields are: " + String.join(", ", EVENT_FIELDS);
        }
        var mismatch = findCause(exception, MismatchedInputException.class);
        if (mismatch != null) {
            String field = eventField(mismatch);
            if (!field.isEmpty()) {
                if (mismatch.getPath().size() > 1) return conversionMessage(mismatch);
                Class<?> type = mismatch.getTargetType();
                String expected = type == String.class ? "a string"
                    : type != null && Map.class.isAssignableFrom(type) ? "a JSON object"
                    : "a value of the required JSON type";
                return field + ": must be " + expected;
            }
            if (mismatch.getPath().isEmpty() && mismatch.getCurrentToken() == null) {
                return MISSING_BODY_MESSAGE;
            }
            return "The body must match the JSON event structure; expected a single event object with correctly typed fields";
        }
        return "The body must match the JSON event structure";
    }

    private String conversionMessage(JacksonException exception) {
        String field = eventField(exception);
        return (field.isEmpty() ? "The body contains" : field + ": contains")
            + " a value that cannot be converted to the required JSON type";
    }

    private String eventField(JacksonException exception) {
        // Only public Event field names are safe to echo; never use arbitrary map keys.
        if (exception.getPath().isEmpty()) return "";
        String field = exception.getPath().getFirst().getPropertyName();
        return field != null && EVENT_FIELDS.contains(field) ? field : "";
    }

    private <T extends Throwable> T findCause(Throwable exception, Class<T> type) {
        // Match SEM-72's bounded traversal: a cyclic cause chain must not hang a request.
        Throwable cause = exception;
        for (int depth = 0; cause != null && depth < 16; depth++, cause = cause.getCause()) {
            if (type.isInstance(cause)) return type.cast(cause);
        }
        return null;
    }

    private ResponseEntity<Map<String, Object>> error(int status, String code, String message) {
        return ResponseEntity.status(status).body(Map.of("error", Map.of("code", code, "message", message)));
    }
}
