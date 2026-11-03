package com.ciberurjc.siem;

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
import com.ciberurjc.siem.services.AlertRepository;
import static org.junit.jupiter.api.Assertions.*;

@org.springframework.test.annotation.DirtiesContext(classMode = org.springframework.test.annotation.DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SiemHttpIntegrationTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
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
    void acceptsAllProducersAndListsTheirStoredAlerts() throws Exception {
        assertEquals(mapper.readTree("{\"alerts\":[]}"), mapper.readTree(request("/alerts", null, null).body()));
        for (String filename : List.of("grupo_2_ids_ejemplo_propuesto.json", "grupo_3_honeypot.json", "grupo_4_scanner.json")) {
            String event = Files.readString(Path.of("contract/examples", filename));
            var response = request("/events", event, "application/json");
            assertEquals(200, response.statusCode(), response.body());
            assertEquals("success", mapper.readTree(response.body()).get("status").asText());
            assertEquals(mapper.readTree(event).get("event_id"), mapper.readTree(response.body()).get("event_id"));
            assertEquals(200, request("/events", event, "application/json").statusCode());
        }
        var listed = mapper.readTree(request("/alerts", null, null).body()).get("alerts");
        assertEquals(3, listed.size());
        for (var alert : listed) {
            assertEquals(mapper.valueToTree(alertRepository.findById(alert.get("alert_id").asText()).orElseThrow()), alert);
            var detail = request("/alerts/" + alert.get("alert_id").asText(), null, null);
            assertEquals(200, detail.statusCode());
            assertEquals(alert, mapper.readTree(detail.body()));
        }
    }

    @Test
    void listsAllStoredAlertsWithExactContractFields() throws Exception {
        var converter = new com.ciberurjc.siem.services.AlertConverter();
        var expected = new java.util.HashSet<String>();
        for (int i = 0; i < 150; i++) {
            var alert = converter.convert(new com.ciberurjc.siem.models.Event(
                "http-query-" + i, "2026-11-03T12:00:00Z", "scanner", "finding", "low",
                "Finding", "Scanner finding", Map.of("target", Map.of("ip", "192.0.2.20"))));
            alertRepository.save(alert);
            expected.add((String) alert.get("alert_id"));
        }
        var response = request("/alerts", null, null);
        assertEquals(200, response.statusCode());
        assertTrue(response.headers().firstValue("Content-Type").orElseThrow().startsWith("application/json"));
        var body = mapper.readTree(response.body());
        assertEquals(1, body.size());
        var alerts = body.get("alerts");
        assertTrue(alerts.isArray());
        assertEquals(150, alerts.size());
        var actual = new java.util.HashSet<String>();
        for (var alert : alerts) {
            assertEquals(11, alert.size());
            String id = alert.get("alert_id").asText();
            assertEquals(mapper.valueToTree(alertRepository.findById(id).orElseThrow()), alert);
            assertTrue(alert.get("source_ip").isNull());
            actual.add(id);
        }
        assertEquals(expected, actual);
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
    void returnsEmptyListAndMissingDetailForEmptyStorage() throws Exception {
        var response = request("/alerts", null, null);
        assertEquals(200, response.statusCode());
        assertEquals(mapper.readTree("{\"alerts\":[]}"), mapper.readTree(response.body()));
        assertEquals(404, request("/alerts/UNKNOWN", null, null).statusCode());
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
            assertEquals(Map.of("status", "success", "message", "Event received successfully", "event_id", model.event_id()), mapper.readValue(response.body(), Map.class));        }
    }

    @Test
    void generatesAndStoresAlertFromReceivedEvent() throws Exception {

        // 1. Leer un evento real de ejemplo del IDS
        String event = Files.readString(
            Path.of("contract/examples/grupo_2_ids_ejemplo_propuesto.json")
        );

        // 2. Obtener el identificador del evento
        String eventId = mapper.readTree(event)
            .get("event_id").asText();

        // 3. Enviar el evento al SIEM
        var response = request(
            "/events",
            event,
            "application/json"
        );

        // 4. Comprobar que se ha recibido correctamente
        assertEquals(200, response.statusCode());

        // 5. Buscar la alerta generada en el repositorio
        var alert = alertRepository.findAll().stream()
            .filter(a -> eventId.equals(a.get("event_id")))
            .findFirst();

        // 6. Comprobar que la alerta existe
        assertTrue(alert.isPresent());

        // 7. Comprobar sus datos
        assertEquals(eventId, alert.get().get("event_id"));
        assertEquals("ids", alert.get().get("source"));
        assertNotNull(alert.get().get("alert_id"));
    }

    @Test
    void acceptsCurrentHoneypotPayloadAndPreservesDetails() throws Exception {
        String input = Files.readString(
            Path.of("contract/examples/grupo_3_honeypot_actual.json")
    );

    var event = mapper.readValue(
        input,
        com.ciberurjc.siem.models.Event.class
    );

    assertEquals(
        mapper.readTree(input),
        mapper.readTree(mapper.writeValueAsString(event))
    );

    assertEquals("/login", event.details().get("ruta"));
    assertTrue(event.details().containsKey("navegador"));
    assertTrue(event.details().containsKey("command"));
    assertNull(event.details().get("command"));

    var response = request("/events", input, "application/json");

    assertEquals(200, response.statusCode(), response.body());
    assertEquals(
        event.event_id(),
        mapper.readTree(response.body()).get("event_id").asText()
        );
    }
}
