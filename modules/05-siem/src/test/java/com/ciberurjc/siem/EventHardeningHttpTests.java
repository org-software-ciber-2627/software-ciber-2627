package com.ciberurjc.siem;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.test.annotation.DirtiesContext;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

@DirtiesContext(classMode = DirtiesContext.ClassMode.BEFORE_EACH_TEST_METHOD)
@Import(InMemoryEventTestConfiguration.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {"server.address=127.0.0.1", "siem.events.max-body-bytes=2048", "siem.alerts.max-stored=3"})
class EventHardeningHttpTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    final HttpClient client = HttpClient.newHttpClient();
    String baseUrl;

    @BeforeEach
    void configureUrl() {
        baseUrl = "http://127.0.0.1:" + environment.getProperty("local.server.port");
    }

    HttpResponse<String> post(HttpRequest.BodyPublisher body) throws Exception {
        var request = HttpRequest.newBuilder(URI.create(baseUrl + "/events"))
            .header("Content-Type", "application/json").POST(body).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    HttpResponse<String> post(Object event) throws Exception {
        return post(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(event)));
    }

    String alerts() throws Exception {
        var request = HttpRequest.newBuilder(URI.create(baseUrl + "/alerts")).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
    }

    Map<String, Object> honeypotEvent() throws Exception {
        return mapper.readValue(Files.readString(Path.of("contract/examples/grupo_3_honeypot.json")), Map.class);
    }

    void assertError(HttpResponse<String> response, int status, String code) {
        assertEquals(status, response.statusCode(), response.body());
        assertEquals(code, mapper.readTree(response.body()).get("error").get("code").asText());
    }

    @Test
    void identicalRetryKeepsOneAlertAndChangedResendIsRejected() throws Exception {
        var original = honeypotEvent();
        assertEquals(200, post(original).statusCode());
        assertEquals(200, post(original).statusCode());

        var tampered = new LinkedHashMap<>(original);
        tampered.put("severity", "low");
        tampered.put("title", "Benign");
        assertError(post(tampered), 409, "EVENT_ID_CONFLICT");

        var listed = mapper.readTree(alerts()).get("alerts");
        assertEquals(1, listed.size());
        assertEquals(original.get("severity"), listed.get(0).get("severity").asText());
        assertEquals(original.get("title"), listed.get(0).get("title").asText());
    }

    @Test
    void sameEventIdFromAnotherSourceIsADifferentAlert() throws Exception {
        var honeypot = honeypotEvent();
        var ids = new LinkedHashMap<String, Object>(mapper.readValue(
            Files.readString(Path.of("contract/examples/grupo_2_ids_ejemplo_propuesto.json")), Map.class));
        ids.put("event_id", honeypot.get("event_id"));
        assertEquals(200, post(honeypot).statusCode());
        assertEquals(200, post(ids).statusCode());
        assertEquals(2, mapper.readTree(alerts()).get("alerts").size());
    }

    @Test
    void rejectsOversizedBodiesWithDeclaredOrChunkedLength() throws Exception {
        var event = new LinkedHashMap<>(honeypotEvent());
        event.put("details", Map.of("blob", "A".repeat(4096)));
        byte[] body = mapper.writeValueAsString(event).getBytes(StandardCharsets.UTF_8);

        assertError(post(HttpRequest.BodyPublishers.ofByteArray(body)), 413, "PAYLOAD_TOO_LARGE");
        assertError(post(HttpRequest.BodyPublishers.ofInputStream(() -> new ByteArrayInputStream(body))),
            413, "PAYLOAD_TOO_LARGE");
        assertEquals("{\"alerts\":[]}", alerts().replace(" ", ""));
    }

    @Test
    void rejectsNewAlertsWhenStorageIsFull() throws Exception {
        var event = new LinkedHashMap<>(honeypotEvent());
        for (int i = 0; i < 3; i++) {
            event.put("event_id", "HP-CAP-" + i);
            assertEquals(200, post(event).statusCode());
        }
        assertEquals(200, post(event).statusCode());
        event.put("event_id", "HP-CAP-3");
        assertError(post(event), 507, "STORAGE_FULL");
        assertEquals(3, mapper.readTree(alerts()).get("alerts").size());
    }

    @Test
    void rejectsEventIdsThatCouldForgeLogLines() throws Exception {
        for (String eventId : List.of("X\nFAKE INFO admin login ok", "a\rb", "with space", "x".repeat(129), "<script>")) {
            var event = new LinkedHashMap<>(honeypotEvent());
            event.put("event_id", eventId);
            assertError(post(event), 400, "VALIDATION_ERROR");
        }
        for (String eventId : List.of("b52ee782-265f-4ec7-a719-484460628ef9", "scan:001.a_b", "x".repeat(128))) {
            var event = new LinkedHashMap<>(honeypotEvent());
            event.put("event_id", eventId);
            assertEquals(200, post(event).statusCode(), eventId);
        }
    }
}
