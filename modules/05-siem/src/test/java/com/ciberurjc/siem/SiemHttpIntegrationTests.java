package com.ciberurjc.siem;

import com.ciberurjc.siem.services.AlertRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SiemHttpIntegrationTests {
    @Autowired
    Environment environment;
    @Autowired
    ObjectMapper mapper;
    @Autowired
    AlertRepository alertRepository;
    final HttpClient client = HttpClient.newHttpClient();
    String baseUrl;

    @BeforeEach
    void configureUrl() {
        baseUrl = "http://127.0.0.1:" + environment.getProperty("local.server.port");
    }

    HttpResponse<String> request(String path, String body, String contentType) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create(baseUrl + path));
        if (body == null)
            builder.GET();
        else
            builder.header("Content-Type", contentType).POST(HttpRequest.BodyPublishers.ofString(body));
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
        for (String filename : List.of("grupo_2_ids_ejemplo_propuesto.json", "grupo_3_honeypot.json",
                "grupo_4_scanner.json")) {
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
        Map<String, Object> valid = mapper
                .readValue(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json")), Map.class);
        for (String field : valid.keySet()) {
            var missing = new LinkedHashMap<>(valid);
            missing.remove(field);
            assertEquals(400, request("/events", mapper.writeValueAsString(missing), "application/json").statusCode(),
                    field);
        }
        for (String field : List.of("event_id", "title", "description", "event_type")) {
            var blank = new LinkedHashMap<>(valid);
            blank.put(field, " ");
            assertEquals(400, request("/events", mapper.writeValueAsString(blank), "application/json").statusCode(),
                    field);
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
        Map<String, Object> valid = mapper
                .readValue(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json")), Map.class);
        for (String field : List.of("event_id", "timestamp", "source", "event_type", "severity", "title",
                "description")) {
            for (Object value : java.util.Arrays.asList(42, 4.2, true, List.of("value"), Map.of("value", "text"),
                    null)) {
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
            assertEquals(400, request("/events", mapper.writeValueAsString(invalid), "application/json").statusCode(),
                    "details: " + value);
        }
    }

    @Test
    void preservesEveryProducerFieldAndReturnsExactReceipt() throws Exception {
        for (String filename : List.of("grupo_2_ids_ejemplo_propuesto.json", "grupo_3_honeypot.json",
                "grupo_4_scanner.json")) {
            String input = Files.readString(Path.of("contract/examples", filename));
            var model = mapper.readValue(input, com.ciberurjc.siem.models.Event.class);
            assertEquals(mapper.readTree(input), mapper.readTree(mapper.writeValueAsString(model)), filename);
            var response = request("/events", input, "application/json");
            assertEquals(200, response.statusCode());
            assertEquals(
                    Map.of("status", "success", "message", "Event received successfully", "event_id", model.event_id()),
                    mapper.readValue(response.body(), Map.class));
        }
    }

    @Test
    void acceptsCurrentHoneypotPayloadAndPreservesDetails() throws Exception {
        String input = Files.readString(
                Path.of("contract/examples/grupo_3_honeypot_actual.json"));

        var event = mapper.readValue(
                input,
                com.ciberurjc.siem.models.Event.class);

        assertEquals(
                mapper.readTree(input),
                mapper.readTree(mapper.writeValueAsString(event)));

        assertEquals("/login", event.details().get("ruta"));
        assertTrue(event.details().containsKey("navegador"));
        assertTrue(event.details().containsKey("command"));
        assertNull(event.details().get("command"));

        var response = request("/events", input, "application/json");

        assertEquals(200, response.statusCode(), response.body());
        assertEquals(
                event.event_id(),
                mapper.readTree(response.body()).get("event_id").asText());
    }

    @Test

    void generatesAndStoresAlertFromReceivedEvent() throws Exception {
        String event = Files.readString(Path.of("contract/examples/grupo_2_ids_ejemplo_propuesto.json"));
        String eventId = mapper.readTree(event).get("event_id").asText();

        var response = request("/events", event, "application/json");
        assertEquals(200, response.statusCode());

        var alert = alertRepository.findAll().stream()
                .filter(a -> eventId.equals(a.get("event_id")))
                .findFirst();

        assertTrue(alert.isPresent());
        assertEquals(eventId, alert.get().get("event_id"));
        assertEquals("ids", alert.get().get("source"));
        assertNotNull(alert.get().get("alert_id"));
    }

    @Test
    void acceptsRealIdsBruteForceEvent() throws Exception {

        String event = """
                {
                "event_id": "IDS-P004-181.25.206.27-20260329T141540Z",
                "timestamp": "2026-03-29T14:15:52Z",
                "source": "ids",
                "event_type": "brute_force",
                "severity": "medium",
                "title": "Posible ataque de fuerza bruta",
                "description": "La IP ha realizado 5 intentos fallidos de login.",
                "details": {
                    "rule_id": "P004",
                    "source_ip": "181.25.206.27",
                    "service": "sshd",
                    "attempts": 5,
                    "usernames": ["pi"],
                    "window_seconds": 60,
                    "first_attempt": "2026-03-29T14:15:40Z",
                    "last_attempt": "2026-03-29T14:15:52Z",
                    "login_success": false
                }
                }
                """;

        var response = request("/events", event, "application/json");

        assertEquals(200, response.statusCode(), response.body());

        var result = mapper.readTree(response.body());

        assertEquals("success", result.get("status").asText());
        assertEquals(
                "IDS-P004-181.25.206.27-20260329T141540Z",
                result.get("event_id").asText());
    }

    @Test
    void acceptsIdsEndpointScanEvent() throws Exception {

        String event = """
                {
                "event_id": "IDS-P005-TEST-001",
                "timestamp": "2026-03-29T14:15:06Z",
                "source": "ids",
                "event_type": "endpoint_scan",
                "severity": "medium",
                "title": "Posible escaneo de endpoints",
                "description": "Se han detectado conexiones a diferentes destinos.",
                "details": {
                    "rule_id": "P005",
                    "source_ip": "203.0.113.10",
                    "targets": 3,
                    "target_ips": [
                    "10.0.0.1",
                    "10.0.0.2",
                    "10.0.0.3"
                    ],
                    "ports": [81, 82, 83],
                    "connections": 3,
                    "threshold": 3,
                    "window_seconds": 60,
                    "first_seen": "2026-03-29T14:15:00Z",
                    "last_seen": "2026-03-29T14:15:06Z"
                }
                }
                """;

        var response = request("/events", event, "application/json");

        assertEquals(200, response.statusCode(), response.body());

        var result = mapper.readTree(response.body());

        assertEquals("success", result.get("status").asText());
        assertEquals("IDS-P005-TEST-001", result.get("event_id").asText());
    }

}
