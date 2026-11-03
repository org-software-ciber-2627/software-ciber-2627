package com.ciberurjc.siem;

import com.ciberurjc.siem.services.AlertRepository;
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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/** HU17 / SEM-33: detalle de una alerta del almacén común. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AlertDetailHttpTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;
    @Autowired AlertRepository alertRepository;

    HttpResponse<String> get(String path) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" +
            environment.getProperty("local.server.port") + path)).GET().build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void returnsStoredAlertWithAllFields() throws Exception {
        // Id propio para no interferir con otros tests que comparten el mismo almacén.
        for (var fixture : mapper.readTree(Files.readString(Path.of("mocks/alerts.json"))).get("alerts")) {
            Map<String, Object> alert = new LinkedHashMap<>(mapper.convertValue(fixture, Map.class));
            String id = "HU17-TEST-" + alert.get("alert_id");
            alert.put("alert_id", id);
            alertRepository.save(alert);
            var response = get("/alerts/" + id);
            assertEquals(200, response.statusCode());
            assertEquals(mapper.valueToTree(alert), mapper.readTree(response.body()));
        }
    }

    @Test
    void unknownAlertReturns404() throws Exception {
        var response = get("/alerts/UNKNOWN");
        assertEquals(404, response.statusCode());
        assertEquals("ALERT_NOT_FOUND", mapper.readTree(response.body()).get("error").get("code").asText());
    }

    @Test
    void alertGeneratedFromEventCanBeConsultedByItsId() throws Exception {
        String event = Files.readString(Path.of("contract/examples/grupo_2_ids_ejemplo_propuesto.json"));
        String eventId = mapper.readTree(event).get("event_id").asText();
        var post = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" +
                environment.getProperty("local.server.port") + "/events"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(event)).build();
        assertEquals(200, HttpClient.newHttpClient().send(post, HttpResponse.BodyHandlers.ofString()).statusCode());

        var stored = alertRepository.findAll().stream()
            .filter(alert -> eventId.equals(alert.get("event_id"))).findFirst();
        assertTrue(stored.isPresent());

        var response = get("/alerts/" + stored.get().get("alert_id"));
        assertEquals(200, response.statusCode());
        assertEquals(mapper.valueToTree(stored.get()), mapper.readTree(response.body()));
    }
}