package com.ciberurjc.siem;

import com.ciberurjc.siem.models.Event;
import com.ciberurjc.siem.repositories.EventRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.dao.DataAccessResourceFailureException;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "server.address=127.0.0.1")
@Import(StorageFailureHttpTests.FailedStorage.class)
class StorageFailureHttpTests {
    @Autowired Environment environment;
    @Autowired ObjectMapper mapper;

    @TestConfiguration(proxyBeanMethods = false)
    static class FailedStorage {
        @Bean
        EventRepository unavailableRepository() {
            return new EventRepository() {
                public void save(Event event) { throw new UnsupportedOperationException(); }
                public Optional<Event> findById(String source, String id) { throw new UnsupportedOperationException(); }
                public SaveResult saveIfAbsent(Event event) {
                    throw new DataAccessResourceFailureException("SQL connection failed: private-test-marker");
                }
            };
        }
    }

    @Test
    void storageFailureReturnsGenericErrorInsteadOfSuccess() throws Exception {
        String input = Files.readString(Path.of("contract/examples/grupo_3_honeypot.json"));
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" +
                environment.getProperty("local.server.port") + "/events"))
            .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(input)).build();
        var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(503, response.statusCode());
        assertEquals(Map.of("error", Map.of("code", "STORAGE_UNAVAILABLE",
            "message", "Event storage is temporarily unavailable")), mapper.readValue(response.body(), Map.class));
        assertFalse(response.body().contains("private-test-marker"));
        assertFalse(response.body().contains("SQL"));
    }
}
