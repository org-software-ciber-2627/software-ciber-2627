package com.ciberurjc.siem;

import com.ciberurjc.siem.config.RequestBodyTooLargeException;
import com.ciberurjc.siem.controller.ApiErrorHandler;
import com.ciberurjc.siem.controller.EventController;
import com.ciberurjc.siem.exceptions.EventValidationException;
import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.services.EventService;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.core.MethodParameter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.validation.BeanPropertyBindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.core.exc.InputCoercionException;
import tools.jackson.databind.json.JsonMapper;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class ApiErrorHandlerTests {
    private final ApiErrorHandler handler = new ApiErrorHandler();

    @Test
    void deduplicatesRepeatedErrorsWithoutDroppingDistinctReasons() throws Exception {
        var errors = new BeanPropertyBindingResult(null, "event");
        for (var entry : java.util.List.of(
                Map.entry("title", "must not be blank"),
                Map.entry("source", "is required"),
                Map.entry("title", "is required"),
                Map.entry("title", "must not be blank"),
                Map.entry("source", "is required"))) {
            errors.addError(new FieldError("event", entry.getKey(), "SECRET_REJECTED_VALUE",
                false, null, null, entry.getValue()));
        }
        var parameter = new MethodParameter(EventController.class.getMethod("receiveEvent", Event.class), 0);
        var response = handler.invalidEvent(new MethodArgumentNotValidException(parameter, errors));

        assertEquals(400, response.getStatusCode().value());
        assertEquals(Map.of("error", Map.of("code", "VALIDATION_ERROR",
            "message", "source: is required; title: is required, must not be blank")), response.getBody());
    }

    @Test
    void distinguishesRealNumericConversionFailureFromMalformedJson() throws Exception {
        // Valid JSON, but its value cannot be represented as a Java int.
        // Event has no int fields: this reproduces the Jackson/handler boundary, not POST /events.
        var cause = numericOverflow();
        var response = handler.invalidJson(new HttpMessageNotReadableException(
            "INTERNAL_CONVERSION_MESSAGE", cause, new MockHttpInputMessage(new byte[0])));

        assertEquals(400, response.getStatusCode().value());
        assertEquals(Map.of("error", Map.of("code", "INVALID_JSON",
            "message", "The body contains a value that cannot be converted to the required JSON type")), response.getBody());
    }

    @Test
    void reportsOnlyKnownEventFieldForNestedConversionFailure() throws Exception {
        var cause = numericOverflow();
        cause.prependPath(Map.class, "SECRET_PROPERTY_NAME");
        cause.prependPath(Event.class, "details");
        var response = handler.invalidJson(new HttpMessageNotReadableException(
            "INTERNAL_CONVERSION_MESSAGE", cause, new MockHttpInputMessage(new byte[0])));

        assertEquals(400, response.getStatusCode().value());
        assertEquals(Map.of("error", Map.of("code", "INVALID_JSON",
            "message", "details: contains a value that cannot be converted to the required JSON type")), response.getBody());
    }

    @Test
    void controlledProcessingRejectionReturns400WithoutExposingItsCause() throws Exception {
        var failure = new EventValidationException("source", "must be one of: ids, honeypot, scanner",
            new IllegalArgumentException("PRIVATE_CONVERTER_DATA"));
        processingFailure(failure).perform(post("/events").contentType("application/json")
                .content(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json"))))
            .andExpect(status().isBadRequest())
            .andExpect(content().json("""
                {"error":{"code":"VALIDATION_ERROR","message":"source: must be one of: ids, honeypot, scanner"}}
                """, true));
    }

    @Test
    void unexpectedIllegalArgumentIsNotClassifiedAsInvalidInput() throws Exception {
        var failure = new IllegalArgumentException("PRIVATE_INTERNAL_DATA");
        var mvc = processingFailure(failure);
        // Standalone MVC propagates an unresolved exception to the servlet container.
        var exception = assertThrows(ServletException.class, () -> mvc.perform(post("/events")
            .contentType("application/json")
            .content(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json")))));
        assertSame(failure, exception.getCause());
    }

    @Test
    void preserves413WhenBodyLimitIsWrappedByJsonReading() throws Exception {
        var failure = new HttpMessageNotReadableException("PRIVATE_READER_DATA",
            new java.io.IOException("PRIVATE_STREAM_DATA", new RequestBodyTooLargeException()),
            new MockHttpInputMessage(new byte[0]));
        processingFailure(failure).perform(post("/events").contentType("application/json")
                .content(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json"))))
            .andExpect(status().isPayloadTooLarge())
            .andExpect(content().json("""
                {"error":{"code":"PAYLOAD_TOO_LARGE","message":"The request body exceeds the maximum allowed size"}}
                """, true));
        var direct = handler.payloadTooLarge(new RequestBodyTooLargeException());
        assertEquals(413, direct.getStatusCode().value());
        assertEquals(Map.of("error", Map.of("code", "PAYLOAD_TOO_LARGE",
            "message", "The request body exceeds the maximum allowed size")), direct.getBody());
    }

    private MockMvc processingFailure(RuntimeException failure) {
        var service = mock(EventService.class);
        doThrow(failure).when(service).processIncomingEvent(any(Event.class));
        return MockMvcBuilders.standaloneSetup(new EventController(service))
            .setControllerAdvice(handler).build();
    }

    private InputCoercionException numericOverflow() throws Exception {
        try (var parser = JsonMapper.builder().build().createParser("2147483648")) {
            parser.nextToken();
            return assertThrows(InputCoercionException.class, parser::getIntValue);
        }
    }
}
