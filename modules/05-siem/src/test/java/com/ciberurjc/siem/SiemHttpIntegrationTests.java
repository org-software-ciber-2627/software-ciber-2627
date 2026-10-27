package com.ciberurjc.siem;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SiemHttpIntegrationTests {
    private static final String SENSITIVE_VALUE = "SEM24_SECRET_DO_NOT_ECHO";
    private static final String UNKNOWN_FIELD_MESSAGE = "The event contains an unknown field; allowed fields are: "
        + "event_id, timestamp, source, event_type, severity, title, description, details";
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    final HttpClient client = HttpClient.newHttpClient();
    String baseUrl;

    @BeforeEach
    void configureUrl() {
        baseUrl = "http://127.0.0.1:" + environment.getProperty("local.server.port");
    }

    HttpResponse<String> request(String path, String body, String contentType) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(baseUrl + path));
        if (body == null) builder.GET();
        else builder.header("Content-Type", contentType).POST(HttpRequest.BodyPublishers.ofString(body));
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void healthIdentifiesTheModule() throws Exception {
        var response = request("/health", null, null);
        assertEquals(200, response.statusCode());
        assertEquals(Map.of("status", "ok", "module", "05-siem"), mapper.readValue(response.body(), Map.class));
    }

    @Test
    void acceptsAllProducersWithoutChangingStaticAlerts() throws Exception {
        String before = request("/alerts", null, null).body();
        for (String filename : List.of("grupo_2_ids_ejemplo_propuesto.json", "grupo_3_honeypot.json", "grupo_4_scanner.json")) {
            String event = Files.readString(Path.of("contract/examples", filename));
            var response = request("/events", event, "application/json");
            assertEquals(200, response.statusCode(), response.body());
            assertEquals("success", mapper.readTree(response.body()).get("status").asText());
            assertEquals(mapper.readTree(event).get("event_id"), mapper.readTree(response.body()).get("event_id"));
            assertEquals(200, request("/events", event, "application/json").statusCode());
        }
        assertEquals(mapper.readTree(before), mapper.readTree(request("/alerts", null, null).body()));
    }

    @Test
    void rejectsMissingFieldsAndInvalidValues() throws Exception {
        Map<String, Object> valid = mapper.readValue(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json")), Map.class);
        for (String field : valid.keySet()) {
            var missing = new LinkedHashMap<>(valid);
            missing.remove(field);
            assertEquals(400, request("/events", mapper.writeValueAsString(missing), "application/json").statusCode(), field);
        }
        for (String field : List.of("event_id", "title", "description", "event_type")) {
            var blank = new LinkedHashMap<>(valid);
            blank.put(field, " ");
            assertEquals(400, request("/events", mapper.writeValueAsString(blank), "application/json").statusCode(), field);
        }
        for (var invalid : List.of(Map.entry("source", "soar"), Map.entry("severity", "urgent"),
                Map.entry("timestamp", "2026-02-30T18:30:15Z"), Map.entry("timestamp", "2026-09-22T18:30:15+00:00"))) {
            var event = new LinkedHashMap<>(valid);
            event.put(invalid.getKey(), invalid.getValue());
            assertEquals(400, request("/events", mapper.writeValueAsString(event), "application/json").statusCode());
        }
        var extra = new LinkedHashMap<>(valid);
        extra.put("source_module", "honeypot");
        assertEquals(400, request("/events", mapper.writeValueAsString(extra), "application/json").statusCode());
        for (String body : List.of("{", "[]", "null", "", "{\"events\":[]}")) {
            var response = request("/events", body, "application/json");
            assertEquals(400, response.statusCode(), body);
            assertTrue(mapper.readTree(response.body()).has("error"));
        }
        assertEquals(415, request("/events", "test", "text/plain").statusCode());
    }

    @Test
    void servesAllFixtureFieldsAndEachAlertDetail() throws Exception {
        var expected = mapper.readTree(Files.readString(Path.of("mocks/alerts.json")));
        var response = request("/alerts", null, null);
        assertEquals(200, response.statusCode());
        assertEquals(expected, mapper.readTree(response.body()));
        assertEquals(3, expected.get("alerts").size());
        for (var alert : expected.get("alerts")) {
            var detail = request("/alerts/" + alert.get("alert_id").asText(), null, null);
            assertEquals(200, detail.statusCode());
            assertEquals(alert, mapper.readTree(detail.body()));
        }
        var missing = request("/alerts/UNKNOWN", null, null);
        assertEquals(404, missing.statusCode());
        assertEquals("ALERT_NOT_FOUND", mapper.readTree(missing.body()).get("error").get("code").asText());
    }

    @Test
    void rejectsWrongTypesWithoutCoercingStringFields() throws Exception {
        Map<String, Object> valid = mapper.readValue(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json")), Map.class);
        for (String field : List.of("event_id", "timestamp", "source", "event_type", "severity", "title", "description")) {
            for (Object value : java.util.Arrays.asList(42, 4.2, true, List.of("value"), Map.of("value", "text"), null)) {
                var invalid = new LinkedHashMap<>(valid);
                invalid.put(field, value);
                var response = request("/events", mapper.writeValueAsString(invalid), "application/json");
                assertEquals(400, response.statusCode(), field + ": " + value);
                assertTrue(mapper.readTree(response.body()).has("error"));
            }
        }
        for (Object value : java.util.Arrays.asList(42, 4.2, true, "text", List.of(), null)) {
            var invalid = new LinkedHashMap<>(valid);
            invalid.put("details", value);
            assertEquals(400, request("/events", mapper.writeValueAsString(invalid), "application/json").statusCode(), "details: " + value);
        }
    }

    @Test
    void preservesEveryProducerFieldAndReturnsExactReceipt() throws Exception {
        for (String filename : List.of("grupo_2_ids_ejemplo_propuesto.json", "grupo_3_honeypot.json", "grupo_4_scanner.json")) {
            String input = Files.readString(Path.of("contract/examples", filename));
            var model = mapper.readValue(input, com.ciberurjc.siem.models.Event.class);
            assertEquals(mapper.readTree(input), mapper.readTree(mapper.writeValueAsString(model)), filename);
            var response = request("/events", input, "application/json");
            assertEquals(200, response.statusCode());
            assertEquals(Map.of("status", "success", "message", "Event received successfully (mock)", "event_id", model.event_id()), mapper.readValue(response.body(), Map.class));
        }
    }

    @Test
    void explainsMissingAndNullRequiredFields() throws Exception {
        var expectedReasons = Map.of(
            "event_id", "is required and must not be blank",
            "timestamp", "is required and must not be blank",
            "source", "is required",
            "event_type", "is required and must not be blank",
            "severity", "is required",
            "title", "is required and must not be blank",
            "description", "is required and must not be blank",
            "details", "is required and must be a JSON object"
        );
        for (var expected : expectedReasons.entrySet()) {
            var event = validEvent();
            event.remove(expected.getKey());
            assertEventError(event, "VALIDATION_ERROR", expected.getKey() + ": " + expected.getValue());
            event.put(expected.getKey(), null);
            assertEventError(event, "VALIDATION_ERROR", expected.getKey() + ": " + expected.getValue());
        }
    }

    @Test
    void explainsEmptyAndWhitespaceOnlyStrings() throws Exception {
        for (String field : List.of("event_id", "timestamp", "event_type", "title", "description")) {
            for (String value : List.of("", " ", "\t\r\n")) {
                var event = validEvent();
                event.put(field, value);
                assertEventError(event, "VALIDATION_ERROR", field + ": is required and must not be blank");
            }
        }
    }

    @Test
    void explainsAllowedSourceAndSeverityValues() throws Exception {
        for (String value : List.of("soar", "IDS", " ids ", "IDENTITY", " identity ", "", " ", SENSITIVE_VALUE)) {
            var event = validEvent();
            event.put("source", value);
            assertEventError(event, "VALIDATION_ERROR", "source: must be one of: ids, honeypot, scanner, identity");
        }
        for (String value : List.of("urgent", "HIGH", " high ", "", " ", SENSITIVE_VALUE)) {
            var event = validEvent();
            event.put("severity", value);
            assertEventError(event, "VALIDATION_ERROR", "severity: must be one of: low, medium, high, critical");
        }
    }

    @Test
    void reportsMultipleFieldsInStableOrderWithoutDuplicateMessages() throws Exception {
        var event = validEvent();
        event.put("title", " ");
        event.put("source", SENSITIVE_VALUE);
        event.put("severity", SENSITIVE_VALUE);
        event.put("description", null);
        var reversed = new LinkedHashMap<String, Object>();
        event.sequencedEntrySet().reversed().forEach(entry -> reversed.put(entry.getKey(), entry.getValue()));

        // Exact equality requires each field and reason once, in alphabetical order,
        // regardless of request property order or repeated validation.
        String expected = "description: is required and must not be blank; "
            + "severity: must be one of: low, medium, high, critical; "
            + "source: must be one of: ids, honeypot, scanner, identity; "
            + "title: is required and must not be blank";
        for (int attempt = 0; attempt < 3; attempt++) {
            assertEventError(event, "VALIDATION_ERROR", expected);
            assertEventError(reversed, "VALIDATION_ERROR", expected);
        }
    }

    @Test
    void identifiesStringFieldsWithIncompatibleTypes() throws Exception {
        for (String field : List.of("event_id", "timestamp", "source", "event_type", "severity", "title", "description")) {
            for (Object value : List.of(42, 4.2, true, List.of(SENSITIVE_VALUE), Map.of("credential", SENSITIVE_VALUE))) {
                var event = validEvent();
                event.put(field, value);
                assertEventError(event, "INVALID_JSON", field + ": must be a string");
            }
        }
    }

    @Test
    void explainsIncompatibleDetailsTypes() throws Exception {
        for (Object value : List.of(42, 4.2, true, SENSITIVE_VALUE, List.of(SENSITIVE_VALUE))) {
            var event = validEvent();
            event.put("details", value);
            assertEventError(event, "INVALID_JSON", "details: must be a JSON object");
        }
    }

    @Test
    void identifiesUnknownPropertiesWithoutEchoingTheirValues() throws Exception {
        for (String field : List.of("source_module", "events")) {
            var event = validEvent();
            event.put(field, SENSITIVE_VALUE);
            assertEventError(event, "INVALID_JSON", UNKNOWN_FIELD_MESSAGE);
        }
    }

    @Test
    void usesSafeFallbackForUnusablePropertyPaths() throws Exception {
        for (String field : List.of("credential\n" + SENSITIVE_VALUE, SENSITIVE_VALUE.repeat(8))) {
            var event = validEvent();
            event.put(field, SENSITIVE_VALUE);
            assertEventError(event, "INVALID_JSON", UNKNOWN_FIELD_MESSAGE);
        }
    }

    @Test
    void doesNotEchoSensitiveUnknownPropertyNames() throws Exception {
        // A secret can be a short ASCII identifier, not just a suspicious-looking name.
        for (String field : List.of(SENSITIVE_VALUE, "token_" + SENSITIVE_VALUE, "Exception")) {
            var event = validEvent();
            event.put(field, SENSITIVE_VALUE);
            assertEventError(event, "INVALID_JSON", UNKNOWN_FIELD_MESSAGE);
        }
    }

    @Test
    void distinguishesMalformedJsonFromMissingBody() throws Exception {
        for (String body : List.of("{", "{]", "{\"event_id\":\"" + SENSITIVE_VALUE + "\",\"timestamp\":}")) {
            assertError(request("/events", body, "application/json"), 400, "INVALID_JSON",
                "Malformed JSON: check the request body syntax");
        }
        for (String body : List.of("", " \t\r\n", "null")) {
            assertError(request("/events", body, "application/json"), 400, "INVALID_JSON",
                "The request body is required and must contain a JSON event object");
        }
    }

    @Test
    void recognizesMissingBodyWithoutDependingOnContentLength() throws Exception {
        for (var publisher : List.of(HttpRequest.BodyPublishers.noBody(),
                HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(new byte[0])),
                HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream("null".getBytes(StandardCharsets.UTF_8))))) {
            var request = HttpRequest.newBuilder(URI.create(baseUrl + "/events"))
                .header("Content-Type", "application/json").POST(publisher).build();
            var response = client.send(request, HttpResponse.BodyHandlers.ofString());
            assertError(response, 400, "INVALID_JSON",
                "The request body is required and must contain a JSON event object");
        }
    }

    @Test
    void stillAcceptsArbitraryPropertyNamesInsideDetails() throws Exception {
        var event = validEvent();
        event.put("details", Map.of(SENSITIVE_VALUE, Map.of("Exception", SENSITIVE_VALUE)));
        var response = request("/events", mapper.writeValueAsString(event), "application/json");
        assertEquals(200, response.statusCode(), response.body());
        assertEquals(Map.of("status", "success", "message", "Event received successfully (mock)",
            "event_id", event.get("event_id")), mapper.readValue(response.body(), Map.class));
        assertFalse(response.body().contains(SENSITIVE_VALUE));
    }

    @Test
    void explainsIncompatibleRootStructures() throws Exception {
        for (String body : List.of("[]", "42", "true", mapper.writeValueAsString(SENSITIVE_VALUE))) {
            assertError(request("/events", body, "application/json"), 400, "INVALID_JSON",
                "The body must match the JSON event structure; expected a single event object with correctly typed fields");
        }
    }

    @Test
    void explainsBothTimestampFailureReasons() throws Exception {
        for (String value : List.of("2026-09-22T18:30:15+00:00", "2026-09-22T18:30:15", SENSITIVE_VALUE)) {
            var event = validEvent();
            event.put("timestamp", value);
            assertEventError(event, "VALIDATION_ERROR", "timestamp: must end with Z (UTC)");
        }
        for (String value : List.of("2026-02-30T18:30:15Z", "2026-09-22T25:30:15Z", SENSITIVE_VALUE + "Z")) {
            var event = validEvent();
            event.put("timestamp", value);
            assertEventError(event, "VALIDATION_ERROR", "timestamp: must represent a valid UTC date-time");
        }
    }

    @Test
    void preservesExactUnsupportedMediaTypeResponse() throws Exception {
        String body = mapper.writeValueAsString(validEvent());
        for (String contentType : List.of("text/plain", "application/xml")) {
            assertError(request("/events", body, contentType), 415, "UNSUPPORTED_MEDIA_TYPE",
                "Content-Type must be application/json");
        }
    }

    @Test
    void acceptsAllowedValuesAndOpenDetailsWithExactReceipt() throws Exception {
        for (String source : List.of("ids", "honeypot", "scanner", "identity")) {
            for (String severity : List.of("low", "medium", "high", "critical")) {
                var event = validEvent();
                event.put("source", source);
                event.put("severity", severity);
                event.put("event_id", "non-uuid-" + source + "-" + severity);
                event.put("timestamp", "2026-09-22T18:30:15.123Z");
                event.put("event_type", "producer_specific_event");
                var details = new LinkedHashMap<String, Object>();
                details.put("credential", SENSITIVE_VALUE);
                details.put("optional", null);
                for (Map<String, Object> value : List.of(Map.<String, Object>of(), details)) {
                    event.put("details", value);
                    var response = request("/events", mapper.writeValueAsString(event), "application/json");
                    assertEquals(200, response.statusCode(), response.body());
                    assertEquals(Map.of("status", "success", "message", "Event received successfully (mock)",
                        "event_id", event.get("event_id")), mapper.readValue(response.body(), Map.class));
                    assertFalse(response.body().contains(SENSITIVE_VALUE));
                }
            }
        }
    }

    @Test
    void acceptsIdentityBruteForceEventWithExactReceipt() throws Exception {
        String event = """
            {
              "event_id": "IDENTITY-BRUTE-FORCE-001",
              "timestamp": "2026-10-27T10:15:00Z",
              "source": "identity",
              "event_type": "fuerza_bruta",
              "severity": "high",
              "title": "Intentos de acceso fallidos en Identidad",
              "description": "Se han detectado 8 intentos de acceso fallidos en 60 segundos.",
              "details": {
                "username": "usuario_prueba",
                "source_ip": "192.0.2.10",
                "failed_attempts": 8,
                "window_seconds": 60,
                "endpoint": "/auth/login"
              }
            }
            """;
        var response = request("/events", event, "application/json");
        assertEquals(200, response.statusCode(), response.body());
        assertEquals(Map.of("status", "success", "message", "Event received successfully (mock)",
            "event_id", "IDENTITY-BRUTE-FORCE-001"), mapper.readValue(response.body(), Map.class));
    }

    private LinkedHashMap<String, Object> validEvent() throws Exception {
        return mapper.readValue(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json")),
            new TypeReference<LinkedHashMap<String, Object>>() {});
    }

    private void assertEventError(Map<String, Object> event, String code, String message) throws Exception {
        assertError(request("/events", mapper.writeValueAsString(event), "application/json"), 400, code, message);
    }

    private void assertError(HttpResponse<String> response, int status, String code, String message) throws Exception {
        assertEquals(status, response.statusCode(), response.body());
        assertTrue(response.headers().firstValue("Content-Type").orElse("").startsWith("application/json"));
        // Compare the entire object: no extra details, stack traces or exception properties are allowed.
        assertEquals(Map.of("error", Map.of("code", code, "message", message)),
            mapper.readValue(response.body(), Map.class));
        String actualMessage = mapper.readTree(response.body()).get("error").get("message").asText();
        for (String forbidden : List.of(SENSITIVE_VALUE, "tools.jackson.", "com.fasterxml.jackson.",
                "com.ciberurjc.", "\tat ")) {
            assertFalse(actualMessage.contains(forbidden), "Response must not expose " + forbidden);
        }
    }
}
