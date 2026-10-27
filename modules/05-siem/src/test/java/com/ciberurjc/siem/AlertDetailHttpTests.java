package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Alert;
import com.ciberurjc.siem.repositories.AlertRepository;
import com.ciberurjc.siem.services.MockAlertService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** HU17 / SEM-33: detalle de una alerta almacenada. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(AlertDetailHttpTests.FakeAlerts.class)
class AlertDetailHttpTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;

    @TestConfiguration(proxyBeanMethods = false)
    static class FakeAlerts {
        @Bean
        AlertRepository fakeAlertRepository(ObjectMapper mapper) throws Exception {
            List<Alert> alerts = mapper.readValue(Files.readString(Path.of("mocks/alerts.json")),
                MockAlertService.AlertFixtures.class).alerts();
            return id -> {
                if (id.equals("FAIL")) {
                    throw new IllegalStateException("SQL connection failed: private-test-marker");
                }
                return alerts.stream().filter(alert -> alert.alert_id().equals(id)).findFirst();
            };
        }
    }

    HttpResponse<String> get(String path) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" +
            environment.getProperty("local.server.port") + path)).GET().build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    void returnsStoredAlertWithAllFields() throws Exception {
        for (var alert : mapper.readTree(Files.readString(Path.of("mocks/alerts.json"))).get("alerts")) {
            var response = get("/alerts/" + alert.get("alert_id").asText());
            assertEquals(200, response.statusCode());
            assertEquals(alert, mapper.readTree(response.body()));
        }
    }

    @Test
    void unknownAlertReturns404() throws Exception {
        var response = get("/alerts/UNKNOWN");
        assertEquals(404, response.statusCode());
        assertEquals("ALERT_NOT_FOUND", mapper.readTree(response.body()).get("error").get("code").asText());
    }

    @Test
    void storageFailureReturns503WithoutInternalDetails() throws Exception {
        var response = get("/alerts/FAIL");
        assertEquals(503, response.statusCode());
        assertEquals("STORAGE_UNAVAILABLE", mapper.readTree(response.body()).get("error").get("code").asText());
        assertFalse(response.body().contains("SQL"));
        assertFalse(response.body().contains("private-test-marker"));
    }
}